package OAuth::Lite2::Formatter;

use strict;
use warnings;

sub new { bless {}, $_[0] }

sub name { die "abstract method" }
sub type { die "abstract method" }

sub format {
    my ($self, $hash) = @_;
    die "abstract method";
}

1;
