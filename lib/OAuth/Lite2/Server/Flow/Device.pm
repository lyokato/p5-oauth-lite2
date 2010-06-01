package OAuth::Lite2::Server::Flow::Device;

use strict;
use warnings;

use parent 'OAuth::Lite2::Server::Flow';

use OAuth::Lite2::Server::Action::Token::DeviceCode;
use OAuth::Lite2::Server::Action::Token::DeviceToken;

sub name { 'device' }

sub new {
    my $class = shift;
    bless {
        token_endpoint_actions => {
            device_code  => OAuth::Lite2::Server::Action::Token::DeviceCode->new,
            device_token => OAuth::Lite2::Server::Action::Token::DeviceToken->new,
        },
    }, $class;
}

1;
