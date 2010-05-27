package OAuth::Lite2::Signer::Algorithm::HMAC_SHA1;

use strict;
use warnings;

use base 'OAuth::Lite2::Signer::Algorithm';
use Digest::SHA;

sub name { "hmac-sha1" }

sub hash {
    my ($self, $key, $text) = @_;
    Digest::SHA::hmac_sha1($text, $key);
}

1;
