package OAuth::Lite2::Model::AuthInfo;

use strict;
use warnings;

use base 'Class::Accessor::Fast';

__PACKAGE__->mk_accessors(qw(
    id
    user_id
    client_id
    scope
    refresh_token

    code
    redirect_uri
));

=head1 NAME

OAuth::Lite2::Model::AuthInfo - model class that represents authorization info.

=head1 ACCESSORS

=head2 id

Identifier of this authorization info.

=head2 user_id

=head2 client_id

=head2 scope

=head2 refresh_token

=head2 code

=head2 redirect_uri

=head1 AUTHOR

Lyo Kato, E<lt>lyo.kato@gmail.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2010 by Lyo Kato

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.8 or,
at your option, any later version of Perl 5 you may have available.

=cut

1;
