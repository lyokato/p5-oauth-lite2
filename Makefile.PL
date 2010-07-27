use strict;
use warnings;

use inc::Module::Install;

name 'OAuth-Lite2';
all_from 'lib/OAuth/Lite2.pm';

requires(
    'Params::Validate'      => 0.95,
    'LWP::UserAgent'        => 0,
    'Try::Tiny'             => 0.06,
    'Class::ErrorHandler'   => 0.01,
    'Class::Accessor::Fast' => 0.34,
    'Data::Dump'            => 1.17,
    'String::Random'        => 0.22,
    'JSON'                  => 2.21,
    'XML::LibXML'           => 1.70,
    'Hash::MultiValue'      => 0.08,
    'URI'                   => 1.54,
    'Digest::SHA'           => 5.48,
    'Scalar::Util'          => 1.23,
    'IO::String'            => 1.08,
    'Plack'                 => 0.09942,
);

tests('t/*.t t/*/*.t t/*/*/*.t');

#author_tests('xt');
test_requires(
    'Test::More' => 0,
    #    'Test::Class' => 0,
);

auto_include;
WriteAll;
