package OAuth::Lite2::Server::Action::Token;

use strict;
use warnings;

sub new {
    my $class = shift;
    bless {}, $class;
}

sub handle_request {
    my ($self, $ctx) = @_;
    die "abstract method";
}

1;
