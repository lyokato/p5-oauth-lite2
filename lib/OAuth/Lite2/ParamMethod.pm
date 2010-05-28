package OAuth::Lite2::ParamMethod;

use strict;
use warnings;

use OAuth::Lite2::Error;

sub new {
    bless {}, $_[0];
}

sub match {
    my ($self, $req) = @_;
    OAuth::Lite2::Error::AbstractMethod->throw;
}

sub parse {
    my ($self, $req) = @_;
    OAuth::Lite2::Error::AbstractMethod->throw;
}

1;
