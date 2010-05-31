package OAuth::Lite2::Util;

use strict;
use warnings;

use base 'Exporter';
use URI::Escape;
use Scalar::Util qw(blessed);
use Hash::MultiValue;

our %EXPORT_TAGS = ( all => [qw(
    encode_param
    decode_param
    parse_content
    build_content
)] );

our @EXPORT_OK = map { @$_ } values %EXPORT_TAGS;

sub encode_param {
    my $param = shift;
    return URI::Escape::uri_escape($param, '^\w.~-');
}

sub decode_param {
    my $param = shift;
    return URI::Escape::uri_unescape($param);
}

sub parse_content {
    my $content = shift;
    my $params  = Hash::MultiValue->new;
    for my $pair (split /\&/, $content) {
        my ($key, $value) = split /\=/, $pair;
        $key   = decode_param($key  ||'');
        $value = decode_param($value||'');
        $params->add($key, $value);
    }
    return $params;
}

sub build_content {
    my $params = shift;
    $params = $params->as_hashref_mixed
        if blessed($params) && $params->isa('Hash::MultiValue');
    my @pairs;
    for my $key (keys %$params) {
        my $k = encode_param($key);
        my $v = $params->{$key};
        if (ref($v) eq 'ARRAY') {
            for my $av (@$v) {
                push(@pairs, sprintf(q{%s=%s}, $k, encode_param($av)));
            }
        } else {
            push(@pairs, sprintf(q{%s=%s}, $k, encode_param($v)));
        }
    }
    return join("&", sort @pairs);
}

1;
