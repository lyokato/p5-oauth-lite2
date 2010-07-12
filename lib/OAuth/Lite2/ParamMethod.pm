package OAuth::Lite2::ParamMethod;

use strict;
use warnings;

sub new {
    bless {}, $_[0];
}

sub match {
    my ($self, $req) = @_;
    die "abstract method";
}

sub parse {
    my ($self, $req) = @_;
    die "abstract method";
}

1;
