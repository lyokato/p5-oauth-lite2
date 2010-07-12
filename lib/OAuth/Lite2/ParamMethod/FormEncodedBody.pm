package OAuth::Lite2::ParamMethod::FormEncodedBody;

use strict;
use warnings;

use parent 'OAuth::Lite2::ParamMethod';
use HTTP::Request;
use HTTP::Headers;
use Carp ();
use bytes ();
use Params::Validate;
use OAuth::Lite2::Util qw(build_content);

sub match {
    my ($self, $req) = @_;
    my $method = lc $req->method;
    return (($method eq 'post'
         ||  $method eq 'put'
         ||  $method eq 'delete')
         && $req->content_type eq 'application/x-www-form-urlencoded'
         && $req->body_parameters->{oauth_token});
}

sub parse {
    my ($self, $req) = @_;
    my $params = $req->body_parameters;
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
    my $method = uc $args{method};
    if ($method eq 'GET' || $method eq 'DELETE') {
        Carp::croak qq{When you request with GET or DELETE method, }
                   .qq{You can't use FormEncodedBody type OAuth parameters.}
    } else {

        my $oauth_params = $args{oauth_params} || {};
        $oauth_params->{oauth_token} = $args{token};

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

        unless ($headers->header("Content-Type")) {
            $headers->header("Content-Type",
                "application/x-www-form-urlencoded");
        }
        my $content_type = $headers->header("Content-Type");
        my $params  = $args{params} || {};
        if ($content_type ne "application/x-www-form-urlencoded") {
            Carp::croak qq{When you use FormEncodedBody-type OAuth parameters,}
                       .qq{Content-Type header must be application/x-www-form-urlencoded.}
        }
        my $content = build_content({%$params, %$oauth_params});
        $headers->header("Content-Length", bytes::length($content));
        my $req = HTTP::Request->new($method, $args{url}, $headers, $content);
        return $req;
    }
}

1;
