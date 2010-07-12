package OAuth::Lite2::Server::GrantHandlers;

use strict;
use warnings;

use OAuth::Lite2::Server::GrantHandler::AuthorizationCode;
use OAuth::Lite2::Server::GrantHandler::BasicCredentials;
use OAuth::Lite2::Server::GrantHandler::RefreshToken;

my %HANDLERS;

sub add_handler {
    my ($class, $type, $handler) = @_;
    $HANDLERS{$type} = $handler;
}

__PACKAGE__->add_handler( 'authorization-code' =>
    OAuth::Lite2::Server::GrantHandler::AuthorizationCode->new );
__PACKAGE__->add_handler( 'basic-credentials' =>
    OAuth::Lite2::Server::GrantHandler::BasicCredentials->new );
__PACKAGE__->add_handler( 'refresh-token' =>
    OAuth::Lite2::Server::GrantHandler::RefreshToken->new );

#__PACKAGE__->add_handler( 'assertion' => );
#__PACKAGE__->add_handler( 'none' => );

sub get_handler {
    my ($class, $type) = @_;
    return $HANDLERS{$type};
}

1;

