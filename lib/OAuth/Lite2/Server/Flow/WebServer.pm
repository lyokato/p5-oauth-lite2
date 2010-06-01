package OAuth::Lite2::Server::Flow::WebServer;

use strict;
use warnings;

use parent 'OAuth::Lite2::Server::Flow';
use OAuth::Lite2::Server::Action::Token::WebServer;

sub name { 'web_server' }

sub new {
    my $class = shift;
    bless {
        token_endpoint_actions => {
            web_server => OAuth::Lite2::Server::Action::Token::WebServer->new,
        },
    }, $class;
}

1;
