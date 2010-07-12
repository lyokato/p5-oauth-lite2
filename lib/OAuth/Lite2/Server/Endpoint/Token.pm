package OAuth::Lite2::Server::Endpoint::Token;

use strict;
use warnings;

use overload
    q(&{})   => sub { shift->psgi_app },
    fallback => 1;

use Plack::Request;
use Try::Tiny;
use Params::Validate;

use OAuth::Lite2::Server::Context;
use OAuth::Lite2::Formatters;
use OAuth::Lite2::Server::Error;
use OAuth::Lite2::Server::GrantHandlers;

sub new {
    my $class = shift;
    my %args = Params::Validate::validate(@_, {
        data_handler => 1
    });
    my $self = bless {
        data_handler   => $args{data_handler},
        grant_handlers => {},
    }, $class;
    return $self;
}

sub support_grant_type {
    my ($self, $type) = @_;
    my $handler = OAuth::Lite2::Server::GrantHandlers->get_handler($type)
        or OAuth::Lite2::Server::Error::UnsupportedGrantType->throw;
    $self->{grant_handlers}{$type} = $handler;
}

sub support_grant_types {
    my $self = shift;
    $self->support_grant_type($_) for @_;
}

sub data_handler {
    my ($self, $handler) = @_;
    $self->{data_handler} = $handler if $handler;
    $self->{data_handler};
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
            # Internal Server Error
            warn $_;
            $res = $req->new_response(500);
        };
        return $res->finalize;
    };

    return $app;
}

sub handle_request {
    my ($self, $request) = @_;

    # from draft-v8, format is specified to JSON only.
    my $format = "json";
    # my $format = $request->param("format") || "json";
    my $formatter = OAuth::Lite2::Formatters->get_formatter_by_name($format)
        || OAuth::Lite2::Formatters->get_formatter_by_name("json");

    my $res = try {

        my $type = $request->param("grant_type")
            or OAuth::Lite2::Server::Error::InvalidRequest->throw(
                description => q{'grant_type' not found},
            );

        my $handler = $self->{grant_handlers}{$type}
            or OAuth::Lite2::Server::Error::UnsupportedGrantType->throw;

        my $data_handler = $self->{data_handler}->new;

        my $client_id = $request->param("client_id")
            or OAuth::Lite2::Server::Error::InvalidRequest->throw(
                description => q{'client_id' not found},
            );

        my $client_secret = $request->param("client_secret")
            or OAuth::Lite2::Server::Error::InvalidRequest->throw(
                description => q{'client_secret' not found},
            );

        $data_handler->validate_client($client_id, $client_secret, $type)
            or OAuth::Lite2::Server::Error::InvalidClient->throw;

        my $ctx = OAuth::Lite2::Server::Context->new({
            request      => $request,
            data_handler => $data_handler,
        });

        my $result = $handler->handle_request($ctx);

        return $request->new_response(200,
            [ "Content-Type"  => $formatter->type,
              "Cache-Control" => "no-store"  ],
            [ $formatter->format($result) ]);

    } catch {

        if ($_->isa("OAuth::Lite2::Server::Error")) {

            my $error_params = { error => $_->type };
            $error_params->{error_description} = $_->description
                if $_->description;
            $error_params->{error_uri} = $_->uri
                if $_->uri;

            return $request->new_response($_->code,
                [ "Content-Type"  => $formatter->type,
                  "Cache-Control" => "no-store"  ],
                [ $formatter->format($error_params) ]);

        } else {

            die $_;

        }

    };
}

1;
