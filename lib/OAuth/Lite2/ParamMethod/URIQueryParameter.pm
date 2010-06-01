package OAuth::Lite2::ParamMethod::URIQueryParameter;

use strict;
use warnings;

use parent 'OAuth::Lite2::ParamMethod';
use HTTP::Request;
use HTTP::Headers;
use bytes ();
use Params::Validate;
use OAuth::Lite2::Util qw(build_content);

sub match {
    my ($self, $req) = @_;
    return exists $req->query_parameters->{oauth_token};
}

sub parse {
    my ($self, $req) = @_;
    my $params = $req->query_parameters;
    my $token = $params->{oauth_token};
    $params->remove('oauth_token');
    return ($token, $params);
}

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
    $oauth_params->{oauth_token} = $args{token};

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

    if ($method eq 'GET' || $method eq 'DELETE') {
        my $query = build_content({%$params, %$oauth_params});
        my $url = sprintf q{%s?%s}, $args{url}, $query;
        my $req = HTTP::Request->new($method, $url, $headers);
        return $req;
    } else {
        my $query = build_content($oauth_params);
        my $url = sprintf q{%s?%s}, $args{url}, $query;
        unless ($headers->header("Content-Type")) {
            $headers->header("Content-Type",
                "application/x-www-form-urlencoded");
        }
        my $content_type = $headers->header("Content-Type");
        my $content = ($content_type eq "application/x-www-form-urlencoded")
            ? build_content($params)
            : $args{content} || build_content($params);
        $headers->header("Content-Length", bytes::length($content));
        my $req = HTTP::Request->new($method, $url, $headers, $content);
        return $req;
    }
}

1;
