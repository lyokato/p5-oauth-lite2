package OAuth::Lite2::ParamMethod::AuthHeader;

use strict;
use warnings;

use parent 'OAuth::Lite2::ParamMethod';
use OAuth::Lite2::Util qw(encode_param decode_param build_content);
use HTTP::Request;
use HTTP::Headers;
use URI;
use bytes ();
use Params::Validate;
use Hash::MultiValue;

=head1 NAME

OAuth::Lite2::ParamMethod::AuthHeader - builder/parser for OAuth 2.0 AuthHeader type of parameter

=head1 SYNOPSIS

    my $meth = OAuth::Lite2::ParamMethod::AuthHeader->new;

    # server side
    if ($meth->match( $plack_request )) {
        my ($token, $params) = $meth->parse( $plack_request );
    }

    # client side
    my $http_req = $meth->request_builder(...);

=head1 DESCRIPTION

builder/parser for OAuth 2.0 AuthHeader type of parameter

=head1 METHODS

=head2 new

Constructor

=head2 match( $plack_request )

Returns true if passed L<Plack::Request> object is matched for the type of this method.

    if ( $meth->match( $plack_request ) ) {
        ...
    }

=cut

sub match {
    my ($self, $req) = @_;
    my $header = $req->header("Authorization");
    return ($header && $header =~ /^\s*(OAuth|Bearer)\s+(.+)$/);
}

=head2 parse( $plack_request )

Parse the L<Plack::Request>, and returns access token and oauth parameters.

    my ($token, $params) = $meth->parse( $plack_request );

=cut

sub parse {
    my ($self, $req) = @_;
    my $header = $req->header("Authorization");
    $header =~ s/^\s*(OAuth|Bearer)\s+([^\s\,]+)//;
    my $token = $2;
    my $params = Hash::MultiValue->new;
    if ($header) {
        $header =~ s/^\s*\,\s*//;
        for my $attr (split /,\s*/, $header) {
            my ($key, $val) = split /=/, $attr, 2;
            $val =~ s/^"//;
            $val =~ s/"$//;
            $params->add($key, decode_param($val));
        }
    }
    return ($token, $params);
}

=head2 build_request( %params )

Build L<HTTP::Request> object.

    my $req = $meth->build_request(
        url          => $url,
        method       => $http_method,
        token        => $access_token,
        oauth_params => $oauth_params,
        params       => $params,
        content      => $content,
        headers      => $headers,
    );

=cut

sub build_request {
    my $self = shift;
    my %args = Params::Validate::validate(@_, {
        url          => 1,
        method       => 1,
        token        => 1,
        oauth_params => 1,
        params       => { optional => 1 },
        content      => { optional => 1 },
        headers      => { optional => 1 },
    });
    my $oauth_params = $args{oauth_params} || {};
    my @pairs = sort map { sprintf q{%s="%s"},
        encode_param($_),
        encode_param($oauth_params->{$_})
    } keys %$oauth_params;

    my $params  = $args{params} || {};
    my $method  = uc $args{method};
    my $headers = $args{headers};
    if (defined $headers) {
        if (ref($headers) eq 'ARRAY') {
            $headers = HTTP::Headers->new(@$headers);
        } else {
            $headers = $headers->clone;
        }
    } else {
        $headers = HTTP::Headers->new;
    }
    my $auth_header = sprintf(q{Bearer %s}, $args{token});
    $auth_header .= ", " . join(", ", @pairs) if @pairs > 0;
    $headers->header(Authorization => $auth_header);

    if ($method eq 'GET' || $method eq 'DELETE') {
        my $url = URI->new($args{url});
        $url->query_form(%$params);
        my $req = HTTP::Request->new($method, $url->as_string, $headers);
        return $req;
    } else {
        unless ($headers->header("Content-Type")) {
            $headers->header("Content-Type",
                "application/x-www-form-urlencoded");
        }
        my $content_type = $headers->header("Content-Type");
        my $content = ($content_type eq "application/x-www-form-urlencoded")
            ? build_content($params)
            : $args{content} || build_content($params);
        $headers->header("Content-Length", bytes::length($content));
        my $req = HTTP::Request->new($method, $args{url}, $headers, $content);
        return $req;
    }
}

=head2 is_legacy( $plack_request )

Returns true if passed L<Plack::Request> object is based draft version 10.

    if ( $meth->is_legacy( $plack_request ) ) {
        ...
    }

=cut

sub is_legacy {
    my ($self, $req) = @_;
    my $header = $req->header("Authorization");
    return ($header && $header =~ /^\s*OAuth\s+(.+)$/);
}

=head1 SEE ALSO

L<OAuth::Lite2::ParamMethods>
L<OAuth::Lite2::ParamMethod>
L<OAuth::Lite2::ParamMethod::FormEncodedBody>
L<OAuth::Lite2::ParamMethod::URIQueryParameter>

=head1 AUTHOR

Lyo Kato, E<lt>lyo.kato@gmail.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2010 by Lyo Kato

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.8 or,
at your option, any later version of Perl 5 you may have available.

=cut

1;
