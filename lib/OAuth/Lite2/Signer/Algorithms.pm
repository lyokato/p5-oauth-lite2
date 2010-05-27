package OAuth::Lite2::Signer::Algorithms;

use strict;
use warnings;

use OAuth::Lite2::Signer::Algorithm::HMAC_SHA1;
use OAuth::Lite2::Signer::Algorithm::HMAC_SHA256;

my %ALGORITHMG;

sub _add_signer {
    my ($class, $signer) = @_;
    $ALGORITHMG{$signer->name} = $signer;
}

__PACKAGE__->_add_signer( OAuth::Lite2::Signer::Algorithm::HMAC_SHA1->new );
__PACKAGE__->_add_signer( OAuth::Lite2::Signer::Algorithm::HMAC_SHA256->new );

sub get_algorithm {
    my ($class, $name) = @_;
    return $ALGORITHMG{$name};
}


1;
