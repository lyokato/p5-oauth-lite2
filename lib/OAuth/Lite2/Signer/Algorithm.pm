package OAuth::Lite2::Signer::Algorithm;

use strict;
use warnings;

use OAuth::Lite2::Error;

sub new { bless {}, $_[0] }

sub hash {
    my ($self, $key, $text) = @_;
    OAuth::Lite2::Error::AbstractMethod->throw;
}

1;
