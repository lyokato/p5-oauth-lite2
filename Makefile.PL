use strict;
use warnings;

use inc::Module::Install;

name 'OAuth-Lite2';
all_from 'lib/OAuth/Lite2.pm';

requires(
    'Parmas::Validate'    => 0,
    'LWP::UserAgent'      => 0,
    'Try::Tiny'           => 0,
    'Class::ErrorHandler' => 0,
    'String::Rondom'      => 0,
    'JSON'                => 0,
    'XML::LibXML'         => 0,
    'Hash::MultiValue'    => 0,
    'URI::Escape'         => 0,
    'Digest::SHA'         => 0,
    'Scalar::Util'        => 0,
    'Plack'               => 0,
);

tests('t/*.t t/*/*.t');

#author_tests('xt');
test_requires(
    'Test::More' => 0,
    #    'Test::Class' => 0,
);

auto_include;
WriteAll;
