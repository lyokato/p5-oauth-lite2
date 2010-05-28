package OAuth::Lite2::Server::Action::Token;

use strict;
use warnings;

use OAuth::Lite2::Error;

sub new {
    my $class = shift;
    bless {}, $class;
}

sub handle_request {
    my ($self, $ctx) = @_;
    OAuth::Lite2::Error::AbstractMethod->throw;
}

1;
