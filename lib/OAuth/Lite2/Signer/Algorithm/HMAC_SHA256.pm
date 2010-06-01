package OAuth::Lite2::Signer::Algorithm::HMAC_SHA256;

use strict;
use warnings;

use parent 'OAuth::Lite2::Signer::Algorithm';
use Digest::SHA;

sub name { "hmac-sha256" }

sub hash {
    my ($self, $key, $text) = @_;
    Digest::SHA::hmac_sha256($text, $key);
}

1;
