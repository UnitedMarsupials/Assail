# An AI-plugin for SpamAssassin

The plugin will submit every email -- a textual portion of one --
to the specified AI-instance inviting it to opine on whether the
message is a spam.

Tested with a locally-running [llama-server](/ggml-org/llama.cpp), but
is likely to work with anything else supporting the [OpenAI REST
API](https://developers.openai.com/api/reference/overview).

## Installation instructions

Save the `AI.pre` and `AI.cf` files into your SpamAssassin configuration
directory -- next to the `local.cf`. Save the entire `AI/` subdirectory
into the same location.

Edit the `AI.cf` to configure the AI-server location and other aspects.

Restart spamd -- if that's, how you use SpamAssassin.
