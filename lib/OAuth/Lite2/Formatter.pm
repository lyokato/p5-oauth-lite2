package OAuth::Lite2::Formatter;

use strict;
use warnings;

use OAuth::Lite2::Error;

sub new { bless {}, $_[0] }

sub name { OAuth::Lite2::Error::AbstractMethod->throw }
sub type { OAuth::Lite2::Error::AbstractMethod->throw }

sub format {
    my ($self, $hash) = @_;
    OAuth::Lite2::Error::AbstractMethod->throw;
}

sub parse {
    my ($self, $content) = @_;
    OAuth::Lite2::Error::AbstractMethod->throw;
}

1;
