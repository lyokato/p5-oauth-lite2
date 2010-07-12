package OAuth::Lite2::Signer::Algorithm;

use strict;
use warnings;

sub new { bless {}, $_[0] }

sub hash {
    my ($self, $key, $text) = @_;
    die "abstract method";
}

1;
