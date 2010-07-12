package OAuth::Lite2::Server::GrantHandlers;

use strict;
use warnings;

use OAuth::Lite2::Server::GrantHandler::AuthorizationCode;
use OAuth::Lite2::Server::GrantHandler::Password;
use OAuth::Lite2::Server::GrantHandler::RefreshToken;

my %HANDLERS;

sub add_handler {
    my ($class, $type, $handler) = @_;
    $HANDLERS{$type} = $handler;
}

__PACKAGE__->add_handler( 'authorization_code' =>
    OAuth::Lite2::Server::GrantHandler::AuthorizationCode->new );
__PACKAGE__->add_handler( 'password' =>
    OAuth::Lite2::Server::GrantHandler::Password->new );
__PACKAGE__->add_handler( 'refresh_token' =>
    OAuth::Lite2::Server::GrantHandler::RefreshToken->new );

#__PACKAGE__->add_handler( 'assertion' => );
#__PACKAGE__->add_handler( 'none' => );

sub get_handler {
    my ($class, $type) = @_;
    return $HANDLERS{$type};
}

1;

