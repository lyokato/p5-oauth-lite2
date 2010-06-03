package OAuth::Lite2::Server::Flow::UsernameAndPassword;

use strict;
use warnings;

use parent 'OAuth::Lite2::Server::Flow';
use OAuth::Lite2::Server::Action::Token::Username;

sub name { 'username' }

sub new {
    my $class = shift;
    bless {
        token_endpoint_actions => {
            username  => OAuth::Lite2::Server::Action::Token::Username->new,
        },
    }, $class;
}

1;
