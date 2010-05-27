package OAuth::Lite2::ParamMethod::FormEncodedBody;

use strict;
use warnings;

use parent 'OAuth::Lite2::ParamMethod';

sub match {
    my ($self, $req) = @_;
    my $method = lc $req->method;
    return ($method eq 'post'
         && $method eq 'put'
         && $method eq 'delete'
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


1;
