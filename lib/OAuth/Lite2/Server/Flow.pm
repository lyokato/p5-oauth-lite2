package OAuth::Lite2::Server::Flow;

use strict;
use warnings;

sub new {
    my $class = shift;
    bless {}, $class;
}

sub name { die 'abstract method' }

sub token_endpoint_actions {
    my $self = shift;
    keys %{$self->{token_endpoint_actions}};
}

sub get_token_endpoint_action {
    my ($self, $action) = @_;
    $self->{token_endpoint_actions}{$action};
}

1;
