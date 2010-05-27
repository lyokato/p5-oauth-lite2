package OAuth::Lite2::Server::Flow::ClientCredential;

use strict;
use warnings;

use base 'OAuth::Lite2::Server::Flow';
use OAuth::Lite2::Server::Action::Token::ClientCredential;

sub name { 'client_credential' }

sub new {
    my $class = shift;
    bless {
        token_endpoint_actions => {
            client_credential  => OAuth::Lite2::Server::Action::Token::ClientCredential->new,
        },
    }, $class;
}


1;
