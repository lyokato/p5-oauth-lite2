package Plack::Middleware::Auth::OAuth2::ProtectedResource;

use strict;
use warnings;

use parent 'Plack::Middleware';

use Plack::Request;
use Plack::Util::Accessor qw(realm data_handler error_uri skip_require_secure);
use Try::Tiny;
use Carp ();

use OAuth::Lite2::Server::Error;
use OAuth::Lite2::ParamMethods;

sub call {
    my ($self, $env) = @_;

    my $error_res = try {

        my $req = Plack::Request->new($env);

        # after draft-v6, signature is not required, so always each connection
        # should be under TLS.
        warn "insecure barere token request" if ($req->secure && !$self->{skip_require_secure});

        my $parser = OAuth::Lite2::ParamMethods->get_param_parser($req)
            or OAuth::Lite2::Server::Error::InvalidRequest->throw;

        # after draft-v6, $params aren't required.
        my ($token, $params) = $parser->parse($req);
        OAuth::Lite2::Server::Error::InvalidRequest->throw unless $token;

        my $dh = $self->{data_handler}->new;

        my $access_token = $dh->get_access_token($token);

        OAuth::Lite2::Server::Error::InvalidToken->throw
            unless $access_token;

        Carp::croak "OAuth::Lite2::Server::DataHandler::get_access_token doesn't return OAuth::Lite2::Model::AccessToken"
            unless $access_token->isa("OAuth::Lite2::Model::AccessToken");

        OAuth::Lite2::Server::Error::ExpiredToken->throw
            unless ($access_token->created_on + $access_token->expires_in > time());

        my $auth_info = $dh->get_auth_info_by_id($access_token->auth_id);

        OAuth::Lite2::Server::Error::InvalidToken->throw
            unless $auth_info;

        Carp::croak "OAuth::Lite2::Server::DataHandler::get_auth_info_by_id doesn't return OAuth::Lite2::Model::AuthInfo"
            unless $auth_info->isa("OAuth::Lite2::Model::AuthInfo");

        $dh->validate_client_by_id($auth_info->client_id)
            or OAuth::Lite2::Server::Error::InvalidToken->throw;

        $dh->validate_user_by_id($auth_info->user_id)
            or OAuth::Lite2::Server::Error::InvalidToken->throw;

        $env->{REMOTE_USER}    = $auth_info->user_id;
        $env->{X_OAUTH_CLIENT} = $auth_info->client_id;
        $env->{X_OAUTH_SCOPE}  = $auth_info->scope if $auth_info->scope;

        return;

    } catch {

        if ($_->isa("OAuth::Lite2::Server::Error")) {

            my @params;
            push(@params, sprintf(q{realm="%s"}, $self->{realm}))
                if $self->{realm};
            push(@params, sprintf(q{error="%s"}, $_->type));
            push(@params, sprintf(q{error_description="%s"}, $_->description))
                if $_->description;
            push(@params, sprintf(q{error_uri="%s"}, $self->{error_uri}))
                if $self->{error_uri};
            # push(@params, sprintf(q{scope='%s'}, $_->scope))
            #     if $_->scope;

            return [
                $_->code,
                [ "WWW-Authenticate" =>"OAuth " . join(', ', @params) ], 
                [ ] 
           ];

        } else {

            # rethrow
            die $_;

        }

    };

    return $error_res || $self->app->($env);
}

=head1 NAME

Plack::Middleware::Auth::OAuth2::ProtectedResource - middleware for OAuth 2.0 Protected Resource endpoint

=head1 SYNOPSIS

    my $app = sub {...};
    builder {
        enable "Plack::Middleware::OAuth2::ProtectedResource",
            data_handler => "YourApp::DataHandler",
            error_uri    => q{http://example.org/error/description};
        enable "Plack::Middleware::JSONP";
        enable "Plack::Middleware::ContentLength";
        $app;
    };

    # and on your controller
    $plack_request->env->{REMOTE_USER};
    $plack_request->env->{X_OAUTH_CLIENT_ID};
    $plack_request->env->{X_OAUTH_SCOPE};

=head1 DESCRIPTION

middleware for OAuth 2.0 Protected Resource endpoint

=head1 METHODS

=head2 call( $env )

=head1 ENV VALUES

After successful verifying authorization within middleware layer,
Following 3 type of values are set in env.

=over 4

=item REMOTE_USER

Identifier of user who grant the client to access the user's protected
resource that is stored on service provider.

=item X_OAUTH_CLIENT

Identifier of the client that accesses to user's protected resource
on beharf of the user.

=item X_OAUTH_SCOPE

Scope parameter that represents what kind of resources that
the user grant client to access.

=back

=head1 AUTHOR

Lyo Kato, E<lt>lyo.kato@gmail.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2010 by Lyo Kato

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.8 or,
at your option, any later version of Perl 5 you may have available.

=cut

1;
