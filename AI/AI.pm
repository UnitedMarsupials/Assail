# Source should remain 7-bit ASCII
package AI;

use Mail::SpamAssassin::Plugin;
use LWP::UserAgent;
use HTTP::Request;
use JSON;
use Encode qw(encode encode_utf8);
use strict;
use warnings;

our @ISA = qw(Mail::SpamAssassin::Plugin);

# Optimized debug wrapper: zero overhead unless -D AI is on
sub
dbg
{
	return unless Mail::SpamAssassin::Logger::would_log('dbg', 'AI');
	Mail::SpamAssassin::Plugin::dbg('AI: ' . join(' ', @_));
}

sub
new($$)
{
	my ($class, $mailsa) = @_;
	my $self = $class->SUPER::new($mailsa);

	if ($Mail::SpamAssassin::VERSION < 4.000000) {
		warn('AI: SpamAssassin 4.0.0+ required');
		return (undef);
	}

	$self->register_eval_rule('check_ai');
	return ($self);
}

sub
parse_config($$)
{
	my ($self, $opts) = @_;
	my $key = $opts->{key};
	my $val = $opts->{value};
	my $conf = $self->{main}->{conf};

	# All ai_* directives are handled uniformly
	if ($key =~ /^ai_(url|max_size|timeout|user_agent|api_key|language)$/) {
		$conf->{$key} = $val;
		$self->inhibit_further_callbacks();
		return (1);
	}
	return (0);
}

sub
check_ai($$)
{
	my ($self, $pms) = @_;
	# 1. Early exit for local (trusted) mail
	return (0) if $pms->{all_trusted};

	my $conf = $pms->{main}->{conf};
	my ($max_size, $url, $user_agent, $api_key, $lang, $timeout, $ary, $text, $ua, $req, $response);

	$max_size   = $conf->{ai_max_size}   // 131072;
	$url        = $conf->{ai_url}        // 'http://localhost:8080/v1/chat/completions';
	$user_agent = $conf->{ai_user_agent} // 'SpamAssassin-AI/1.0';
	$api_key    = $conf->{ai_api_key}    // undef;
	$lang       = $conf->{ai_language}   // 'English';
	$timeout    = $conf->{ai_timeout}    // 181;

	my $subj = $pms->get('Subject') // '';
	$subj =~ s/\s+$//;
	$text = "Subject: $subj\n\n";
	my %processed_alternatives;

	foreach my $p ($pms->get_message()->find_parts(qr/./)) {
		my $ctype = lc($p->get_header('content-type') // 'unknown');
		my $parent = $p->{parent} // $p;

		next if ($ctype =~ m{^multipart/});

		if ($parent->{type} =~ m{multipart/alternative}i) {
			next if exists $processed_alternatives{$parent};
		}

		my $fname = $p->get_header('content-disposition') // '';
		$fname = ($fname =~ /filename=["']?([^"';]+)["']?/i) ? " [Filename: $1]" : '';

		my $new_addition = '';

		if ($ctype =~ m{text/(?:plain|html)}i) {
			my $body = $p->decode() // '';
			next if (length($body) < 5);

			if ($parent->{type} =~ m{multipart/alternative}i) {
				$processed_alternatives{$parent} = 1;
			}

			if ($ctype =~ /html/) {
				$body =~ s/<[^>]+>/ /g;
				$body =~ s/\s+/ /g;
				$new_addition = "--- Part: $ctype$fname (Converted) ---\n" . $body . "\n";
			} else {
				$new_addition = "--- Part: $ctype$fname ---\n" . $body . "\n";
			}
		} else {
			my $size = length($p->decode() // '');
			$new_addition = "--- Attachment: $ctype$fname ($size bytes) ---\n[Binary skipped]\n\n";
		}

			# Check size limit before appending
		my $current_len = length($text);
		my $addition_len = length($new_addition);

		if ($current_len + $addition_len > $max_size) {
			my $remaining = $max_size - $current_len;
			if ($remaining > 0) {
				$text .= substr($new_addition, 0, $remaining);
			}
			last; # Reached size limit, exit loop
		}

		$text .= $new_addition;
	}

	# Check minimum text threshold (e.g. 20 characters)
	# to avoid bothering the AI with trivial content
	if (length($text) < 20) {
		dbg("Text too short, only", length($text), "characters");
		$pms->set_tag('AI_STATUS', "Too little text for AI analysis");
		return (0);
	}

	# 3. Build the prompt (Structured Output JSON)
	my $prompt = 'Analyze for spam. Reply ONLY JSON '.
	    '{verdict:SPAM|HAM|UNSURE, reason:string}. ' .
	    "Write the 'reason' field in $lang:\n\n" . $text;

	my $payload = {
		model => 'local-model',
		messages => [{ role => 'user', content => $prompt }],
		response_format => {
			type => 'json_schema',
			json_schema => {
				name => 'spam_verdict',
				strict => 1,
				schema => {
					type => 'object',
					properties => {
						verdict => {
							type => 'string',
							enum => ['SPAM', 'HAM', 'UNSURE']
						},
						reason  => {
							type => 'string'
						}
					},
					required => ['verdict', 'reason'],
					additionalProperties => 0
				}
			}
		},
		temperature => 0
	};

	my $json_body = encode_json($payload);

	# 4. Send the request (timeout sized for a 32B model)
	$ua = LWP::UserAgent->new(timeout => $timeout);
	$ua->agent($user_agent);
	$req = HTTP::Request->new(POST => $url);
	$req->header('Content-Type' => 'application/json');
	$req->header('Authorization' => "Bearer $api_key") if defined($api_key);
	$req->content($json_body);

	$response = $ua->request($req);
	dbg('Response status', $response->status_line);
	dbg('Response content', $response->decoded_content());

	# Network error
	if (!$response->is_success) {
		my $err = $response->status_line;
		warn('Network Error: ', $err);
		$pms->set_tag('AI_STATUS', "Error: $err");
		return (0);
	}

	# 5. Parse the result (llama-server b8064+ format)
	my $outer = eval { decode_json($response->content) };
	if ($@ || !$outer) {
		warn('Failed to parse AI response JSON: ', ($@ // "Invalid structure"));
		$pms->set_tag('AI_STATUS', "Error: Invalid JSON response");
		return (0);
	}
	my $raw = $outer->{choices}->[0]->{message}{content} // '';

	# Structure error
	if (!$raw) {
		warn('Empty or invalid AI response structure');
		$pms->set_tag('AI_STATUS', "Error: AI response empty");
		return (0);
	}

	dbg("Raw result from AI:", $raw);

	my $ai_json = eval { JSON->new->decode($raw) };
	if ($@ || !$ai_json || !$ai_json->{verdict}) {
		warn('Malformed JSON content in response:',
		    ($@ // "Invalid format"));
		$pms->set_tag('AI_STATUS', "Status: Malformed AI Content");
		return (0);
	}

	# Successful verdict
	my $v = uc($ai_json->{verdict});
	my $r = $ai_json->{reason} // 'No reason';
	if ($r =~ /[^\x00-\x7F]/) {
		# If the reason contains non-ASCII characters, SA
		# may encode it into UTF. Replace ASCII spaces into
		# UTF blanks so they survive:
		$r =~ s/ /\x{A0}/g;
	}

	my $rule = "AI_" . $v;

	# Set tags (set_tag for SA headers, tag_data for reliability)
	$pms->set_tag('AI_STATUS', $r);

	if (!$pms->got_hit($rule)) {
		dbg("Rule not found in config:", $rule);
		$pms->got_hit('AI_UNSURE');
	}

	return (1);
}

1;
