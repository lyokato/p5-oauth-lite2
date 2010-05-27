package OAuth::Lite2::ParamMethod::AuthHeader;

use strict;
use warnings;

use parent 'OAuth::Lite2::ParamMethod';
use OAuth::Lite2::Util qw(decode_param);

sub match {
    my ($self, $req) = @_;
    my $header = $req->header("Authorization");
    return ($header && $header =~ /^Token (.*)$/);
}

sub parse {
    my ($self, $req) = @_;
    my $header = $req->header("Authorization");
    $header =~ s/^\s*Token\s*//;
    my $params = {};
    for my $attr (split /,\s*/, $header) {
        my ($key, $val) = split /=/, $attr, 2;
        $val =~ s/^"//;
        $val =~ s/"$//;
        $params->{$key} = decode_param($val);
    }
    my $token = delete $params->{token};
    return ($token, $params);
}


1;
