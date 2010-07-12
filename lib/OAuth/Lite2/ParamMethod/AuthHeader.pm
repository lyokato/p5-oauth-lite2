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

sub match {
    my ($self, $req) = @_;
    my $header = $req->header("Authorization");
    return ($header && $header =~ /^\s*OAuth\s+(.+)$/);
}

sub parse {
    my ($self, $req) = @_;
    my $header = $req->header("Authorization");
    $header =~ s/^\s*OAuth\s+([^\s\,]+)//;
    my $token = $1;
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
    my $auth_header = sprintf(q{OAuth %s}, $args{token});
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


1;
