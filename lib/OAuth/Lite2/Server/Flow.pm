package OAuth::Lite2::Server::Flow;

use strict;
use warnings;

use OAuth::Lite2::Error;

sub new {
    my $class = shift;
    bless {}, $class;
}

sub name { OAuth::Lite2::Error::AbstractMethod->throw }

sub token_endpoint_actions {
    my $self = shift;
    keys %{$self->{token_endpoint_actions}};
}

sub get_token_endpoint_action {
    my ($self, $action) = @_;
    $self->{token_endpoint_actions}{$action};
}

1;
