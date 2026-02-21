package AI;

use Mail::SpamAssassin::Plugin;
use LWP::UserAgent;
use HTTP::Request;
use JSON;
use Encode qw(encode encode_utf8);
use strict;
use warnings;

our @ISA = qw(Mail::SpamAssassin::Plugin);

# Оптим╕зована обгортка для дебагу: нульове навантаження, якщо -D AI вимкнено
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

	bless($self, $class);
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

	# Додано ai_language до дозволених параметр╕в
	if ($key =~ /^ai_(url|max_size|user_agent|api_key|language)$/) {
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
	# 1. Ранн╕й вих╕д для локально╖ пошти
	return (0) if $pms->{all_trusted};

	my $conf = $pms->{main}->{conf};
	my ($max_size, $url, $user_agent, $api_key, $lang, $ary, $text, $ua, $req, $response);

	$max_size   = $conf->{ai_max_size}   || 131072;
	$url        = $conf->{ai_url}        || 'http://localhost:8080/v1/chat/completions';
	$user_agent = $conf->{ai_user_agent} // 'SpamAssassin-AI/1.0';
	$api_key    = $conf->{ai_api_key}    // undef;
	$lang       = $conf->{ai_language}   // 'English';

	$text = "Subject: " . ($pms->get('Subject') // '') . "\n\n";
	$max_size = $self->{conf}->{ai_max_size} // 12000;
	$text = "";
	my %processed_alternatives;

	foreach my $p ($pms->{msg}->find_parts(qr/./)) {
		my $ctype = lc($p->get_header('content-type') // 'unknown');
		my $parent = $p->{parent} // $p;

		next if ($ctype =~ m{^multipart/});

		if ($parent->{type} =~ m{multipart/alternative}i) {
			next if exists $processed_alternatives{$parent};
		}

		my $fname = $p->get_header('content-disposition') // '';
		$fname = ($fname =~ /filename=["']?([^"';]+)["']?/i) ? " [Filename: $1]" : "";

		my $new_addition = "";

		if ($ctype =~ m{text/(?:plain|html)}i) {
			my $body = $p->decode() // "";
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

		# Перев╕рка л╕м╕ту перед додаванням
		my $current_len = length($text);
		my $addition_len = length($new_addition);

		if ($current_len + $addition_len > $max_size) {
			my $remaining = $max_size - $current_len;
			if ($remaining > 0) {
				$text .= substr($new_addition, 0, $remaining);
			}
			last; # Досягли л╕м╕ту, виходимо з циклу
		}

		$text .= $new_addition;
	}

	# Перев╕ря╓мо м╕н╕мальний пор╕г (наприклад, 20 символ╕в),
	# щоб не турбувати Ш╤ через др╕бниц╕
	if (length($text) < 20) {
		dbg("Text too short, only", length($text), "characters");
		pms->set_tag('AI_STATUS', "Too little text for AI analysis");
		return (0);
	}

	# 3. Форму╓мо запит (Structured Output JSON)
	my $prompt = 'Analyze for spam. Reply ONLY JSON '.
	    '{verdict:SPAM|HAM|UNSURE, reason:string}. ' .
	    "Write the 'reason' field in $lang:\n\n" . $text;

	my $payload = {
		model => "local-model",
		messages => [{ role => "user", content => $prompt }],
		response_format => {
			type => "json_schema",
			json_schema => {
				name => "spam_verdict",
				strict => 1,
				schema => {
					type => "object",
					properties => {
						verdict => {
							type => "string",
							enum => ["SPAM", "HAM", "UNSURE"]
						},
						reason  => {
							type => "string"
						}
					},
					required => ["verdict", "reason"],
					additionalProperties => 0
				}
			}
		},
		temperature => 0
	};

	my $json_body = encode_json($payload);

	# 4. Мережевий запит (Таймаут 120с для 32B модел╕)
	$ua = LWP::UserAgent->new(timeout => 181);
	$ua->agent($user_agent);
	$req = HTTP::Request->new(POST => $url);
	$req->header('Content-Type' => 'application/json');
	$req->header('Authorization' => "Bearer $api_key") if defined($api_key);
	$req->content($json_body);

	$response = $ua->request($req);
	dbg('Response status', $response->status_line);
	dbg('Response content', $response->decoded_content());

	# Помилка мереж╕
	if (!$response->is_success) {
		my $err = $response->status_line;
		warn('Network Error: ', $err);
		$pms->set_tag('AI_STATUS', "Error: $err");
		$pms->got_hit('AI_ERROR');
		return (0);
	}

	# 5. Обробка результату (llama-server b8064+ format)
	my $outer = eval { decode_json($response->content) };
	my $raw = $outer->{choices}->[0]->{message}{content} // '';

	# Помилка структури
	if (!$raw) {
		warn("Empty or invalid AI response structure");
		$pms->set_tag('AI_STATUS', "Error: AI response empty");
		$pms->got_hit("AI_ERROR");
		return (0);
	}

	dbg("Raw result from AI:", $raw);

	my $ai_json = eval { JSON->new->decode($raw) };
	if ($@ || !$ai_json || !$ai_json->{verdict}) {
		warn("Malformed JSON content in response:",
		    ($@ // "Invalid format"));
		$pms->set_tag('AI_STATUS', "Status: Malformed AI Content");
		$pms->got_hit("AI_ERROR");
		return (0);
	}

	# Усп╕шний вердикт
	my $v = uc($ai_json->{verdict});
	my $r = $ai_json->{reason} // 'No reason';
	if ($r =~ /[^\x00-\x7F]/) {
		# If the reason contains non-ASCII characters, SA
		# may encode it into UTF. Replace ASCII spaces into
		# UTF blanks so they survive:
		$r =~ s/ /\x{A0}/g;
	}

	my $rule = "AI_" . $v;

	# Встановлю╓мо ТЕГИ (set_tag для SA, tag_data для над╕йност╕)
	$pms->set_tag('AI_STATUS', $r);

	if (!$pms->got_hit($rule)) {
		dbg("Rule not found in config:", $rule);
		$pms->got_hit("AI_UNSURE");
	}

	return (1);
}

1;
