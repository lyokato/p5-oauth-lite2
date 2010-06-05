package Plack::Middleware::Auth::OAuth2::ProtectedResource;

use strict;
use warnings;

use parent 'Plack::Middleware';

use Plack::Request;
use Plack::Util::Accessor qw(realm data_handler);
use Try::Tiny;

use OAuth::Lite2::Error;
use OAuth::Lite2::Server::EndPoint::ProtectedResource;

sub call {
    my ($self, $env) = @_;

    my $handler = OAuth::Lite2::Server::EndPoint::ProtectedResource->new(
        data_handler => $self->data_handlr, 
    );

    try {

        $handler->validate($env);

    } catch {


    };

    my $res = $self->app->($env);
    return $res;
}

1;
