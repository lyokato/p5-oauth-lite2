package OAuth::Lite2::Server::Flow::ClientCredentials;

use strict;
use warnings;

use parent 'OAuth::Lite2::Server::Flow';
use OAuth::Lite2::Server::Action::Token::ClientCredentials;

sub name { 'client_credential' }

sub new {
    my $class = shift;
    bless {
        token_endpoint_actions => {
            client_credential  => OAuth::Lite2::Server::Action::Token::ClientCredentials->new,
        },
    }, $class;
}

1;
