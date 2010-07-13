package TestPR;

use strict;
use warnings;

use overload
    q(&{})   => sub { shift->psgi_app },
    fallback => 1;

use Plack::Request;
use Try::Tiny;
use Params::Validate;
use TestDataHandler;

use Plack::Middleware::Auth::OAuth2::ProtectedResource;

sub new {
    my $class = shift;
    bless { }, $class;
}

sub psgi_app {
    my $self = shift;
    return $self->{psgi_app}
        ||= $self->compile_psgi_app;
}

sub compile_psgi_app {
    my $self = shift;
    my $app = sub {
        my $env = shift;
        my $req = Plack::Request->new($env);
        my $res; try {
            $res = $self->handle_request($req);
        } catch {
            $res = $req->new_response(500);
        };
        return $res->finalize;
    };
    return Plack::Middleware::Auth::OAuth2::ProtectedResource->wrap($app,
        realm        => 'resource.example.org',
        data_handler => 'TestDataHandler',
    );
}

sub handle_request {
    my ($self, $request) = @_;
    return $request->new_response(200,
        ["Content-Type" => "application/json"],
        [ sprintf("{user: '%s', scope: '%s'}",
            $request->env->{REMOTE_USER},
            $request->env->{X_OAUTH_SCOPE})]
    );
}

1;
