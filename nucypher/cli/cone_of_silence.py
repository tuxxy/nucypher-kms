"""
This file is part of nucypher.

nucypher is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

nucypher is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with nucypher.  If not, see <https://www.gnu.org/licenses/>.
"""


import click


@click.command()
@click.argument('action')
def cone_of_silence(action):
    """
    An isolated process for performing cryptographic operations for NuCypher.
    """

    if action == 'start':
        click.secho("Starting...")
        return

    if action == 'stop':
        click.secho("Stopping...")
        return
