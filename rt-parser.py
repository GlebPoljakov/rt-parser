#!/usr/bin/env python

import sys
from tabulate import tabulate
import click
import inspect #Check a need for this import.

# TODO: Write class RoutingTable, or allRoutingTables


def slices(s, *args):
    """
        Slicing rows by field lengths.
    """
    position = 0
    for length in args:
        yield s[position:position + length]
        position += length

def str2hexstr(inStr):
    """
        Return string chars in HEX as a string.
    """
    return ":".join("{:02x}".format(ord(c)) for c in inStr)

def parseRoutingTableHuaweiCE(inFile):
    """
        Parsing dumps of 'display ip routing' and 'display ip routing all-vpn' of Huawei CE12800 and may be of other Huawei CE devices.
    """

    allRoutingTables = []

    thisRTName = ''
    thisRTLines = {}

    rtDelimiter = '------------------------------------------------------------------------------' # Line that delimits VPN-Instances in input

    lineCounter = -1

    while True:
        line = inFile.readline()
        # if it is an end of input, set line as rtDelimiter to invoke addition of routing info to allRoutingTables.
        if not line:
            line = rtDelimiter

        lineCounter = lineCounter + 1
        line = line.strip('\n\r')       # Strip linendings

        if gDebug >= 3:
            print 'Readed line:%s' % line
        if gDebug >= 4:
            print '\tHex: %s' % str2hexstr(line)

        #Skip empty lines
        if line.strip() == '': continue

        # Is its new VPN-Instance Routing Table?
        if line == rtDelimiter:
            if gDebug >=3:
                print 'Get rtDelimiter on input.'

            #append resulting RT-List with new instance of VPN and VPN routes, do it only if it is not a first iteration.
            if thisRTName != '':
                if gDebug >= 3:
                    print 'Append Routing Table %s to allRoutingTables.' % thisRTName
                allRoutingTables.append({'Name': thisRTName, 'RouteRecords': thisRTLines })

            # Read new VPN-instance name
            line = inFile.readline()

            if gDebug >= 3:
                print '\tSearch for VPN-Name: "%s" and Hex: "%s"' % (line, str2hexstr(line))

            lineCounter = lineCounter + 1

            if 'Routing Table' not in line:
                print 'Could not parse input.'
                break

            thisRTName = line[16:].strip()
            thisRTLines = {}

            if gDebug >=3:
                print 'New RT: %s' % thisRTName

            # Skip header lines
            for x in xrange(3):
                line = inFile.readline().strip()
                lineCounter = lineCounter + 1

                if gDebug >= 3:
                    print 'SKIP - Line: "%s"' % line
                    print '\tHex: "%s"' % str2hexstr(line)

            lineCounter = lineCounter + 1
            continue

        #if it is first iteration and we didn't yet find VPN-Instance Name, search for it first.
        if thisRTName == '': continue

        # Else parse the record
        RouteLine = list(slices(line, 20, 8, 5, 11, 6, 16, 200))

        """
            Parse RecordLine to RouteRecord dict:
                '10.1.1.0/24': {
                                'Protocol': 'OSPF',
                                'Preference': 150,
                                'Cost': 401,
                                'Flags': 'D',
                                'Nexthop': ['10.10.10.1',],
                                'Interface': ['Vlanif1409',],
                                }
        """

        Prefix = RouteLine[0].strip()

        # if this RouteLine not a continue of a previous one,
        if Prefix != '':
            #Parse a RouteLine into a RouteRecord and append it
            thisRTLines[Prefix] = {
                                    'Protocol': RouteLine[1].strip(),
                                    'Preference': RouteLine[2].strip(),
                                    'Cost': RouteLine[3].strip(),
                                    'Flags': RouteLine[4].strip(),
                                    'Nexthop': [RouteLine[5].strip(),],
                                    'Interface': [RouteLine[6].strip(),],
                        }
            lastPrefix = Prefix
        else:
            # this RouteLine is continue of previous, thus we need append info in this line into a previous RouteRecord
            try:
                thisRTLines[lastPrefix]['Nexthop'].append(RouteLine[5].strip())
                thisRTLines[lastPrefix]['Interface'].append(RouteLine[6].strip())
            except IndexError:
                print 'Current Line:%s \n\tHex: %s' % (line, str2hexstr(line))
                print 'Current RouteLine:%s \n\tHex: %s' % (RouteLine, str2hexstr(RouteLine))
                print 'Error on line %d' % lineCounter
                raise
                quit()

    return allRoutingTables

def getRoute(vpn, prefix):
    """
        Function for searching specified prefix in allRoutingTables
    """
    res = []
    resrt = []

    for RT in allRoutingTables:
        if (RT['Name'] == vpn) or (vpn == ''):
            for line in RT['RouteRecords']:
                if line['Prefix'] == prefix:
                    resrt.append(line)
            res.append({'Name':RT['Name'],'RouteRecords':resrt})

    return res

def printEntrypoint(allRoutingTables, outputFormat,):
    """
        General printing logic with invoking output format function.

        Variables:
            outputFormat - is type of output (plaintext, html, yaml, etc)
            allRoutingTables - routing information
    """
    if gDebug >= 2:
        print '\tprintEntrypoint aruments:'
        for arg, val in locals().items():
            if type(val) is list:
                val = 'list with %s entries.' % len(val)
            click.echo('\t\t"%s" is "%s"' % (arg, val))

    doOutput = {
        'yaml': printYaml,
        'plain': printPlain,
        'html': printHtml,
        'tabulate': printTabulate,
    }

    doOutput.get(outputFormat, 'plain')(allRoutingTables)

def printComparedEntrypoint(allRoutingTables, outputFormat, inputVpnInstance, inputProtocol, bDiffOnly):
    """
        General printing logic with invoking output format function.

        Variables:
            inputVpnInstance - filter of VPNs, type is list
            inputProtocol - specifies which protocols display
            outputFormat - is type of output (plaintext, html, yaml, etc)
            allRoutingTables - routing information
    """
    if gDebug >= 2:
        print '\tprintEntrypoint aruments:'
        for arg, val in locals().items():
            if type(val) is list:
                val = 'list with %s entries.' % len(val)
            click.echo('\t\t"%s" is "%s"' % (arg, val))

    tobePrinted = []

    for RT in allRoutingTables:
        #Skip this VPN if it not in filter-list, if filter-list not blank
        if (
            (RT['Name'] in inputVpnInstance) or
            (inputVpnInstance == ())
        ):
            if gDebug >= 3:
                click.echo('\t\tVPN-Instance %s is in filter-list. Add it to print list.' % RT['Name'])

            tobePrintedRTRRs = []

            for rec, recval in RT['RouteRecords'].items():
                try:
                    #if Protocol or ProtocolTobe is not int specified Protocols, goto next.
                    if not (
                        (recval['Protocol'] in inputProtocol) or
                        (recval['ProtocolTobe'] in inputProtocol) or
                        (inputProtocol == ())
                    ):
                        continue

                    lRouteAsis = recval['Protocol'], recval['Nexthop'], recval['Interface']
                    lRouteTobe = recval['ProtocolTobe'], recval['NexthopTobe'], recval['InterfaceTobe']
                    bRouteDiffer = lRouteAsis != lRouteTobe

                    if gDebug >= 4:
                        click.echo('\t\t\tRouteAsis: {0}'.format(lRouteAsis))
                        click.echo('\t\t\tRouteTobe: {0}'.format(lRouteTobe))
                        click.echo('\t\t\tRouteAsis and RouteTobe has a differece: {0}'.format(bRouteDiffer))

                    difference = '!=>' if bRouteDiffer else ''

                    #if need print only diffs
                    if bDiffOnly:
                        if not difference:
                            continue

                    tobePrintedRTRRs.append([
                        difference,
                        rec,
                        recval['Protocol'], recval['Nexthop'], recval['Interface'],
                        recval['ProtocolTobe'], recval['NexthopTobe'], recval['InterfaceTobe']
                    ])
                except KeyError:
                    if gDebug >= 4:
                        print '\t\t Recval: %s' % recval
                        raise
            #ENDFOR

            tobePrinted.append({'Name':RT['Name'],'RouteRecords':tobePrintedRTRRs})
        #ENDIF
    #ENDFOR

    printEntrypoint(tobePrinted, outputFormat)

def printYaml(allRoutingTables):
    """
        Output Routing Table in YAML-format
    """
    import yaml
    for RT in allRoutingTables:
        print 'VPN: %s \t\t Routes: %s' % (RT['Name'], len(RT['RouteRecords']))
        print yaml.dump(RT['RouteRecords'], default_flow_style=False)

#TODO: move column names, avoid hardcoding its in tabulate invoke.
def printTabulate(allRoutingTables):
    """
        Output Routing Table in Plain text with Tabulate
    """

    for RT in allRoutingTables:
        print 'VPN: %s \t\t Routes: %s' % (RT['Name'], len(RT['RouteRecords']))

        print tabulate( RT['RouteRecords'],
                       ['Diff', 'Prefix', 'Protocol', 'Nexthop', 'Interface', 'ProtocolTobe', 'NexthopTobe', 'InterfaceTobe'],
                       tablefmt="pipe"
                      )

def printPlain(allRoutingTables):
    """
        Output Routing Table in Plain text
    """

    for RT in allRoutingTables:
        click.echo('============================================================================================================')
        click.echo('VPN: %s \t\t Routes: %s' % (RT['Name'], len(RT['RouteRecords'])))
        click.echo('============================================================================================================')

        for rec, recval in RT['RouteRecords'].items():
            click.echo('{0}\t{1}'.format(rec,recval))

def printHtml(allRoutingTables):
    print 'printHtml(%s, %s)' % (allRoutingTables, inputVpnInstance)

@click.group()
@click.option('-d', '--debug', count=True)
@click.option('--output', 'outf', type=click.Choice(['plain', 'html', 'yaml', 'tabulate']),
              default='plain',
              help='Output format')
def cli(debug, outf):
    global gDebug
    gDebug = debug

    global outputFormat
    outputFormat = outf

@cli.command()
@click.option('-vpn', '--vpn-instance', 'inputVpnInstance',
              default='',
              help='Parce only this one vpn-instance. Case sencetive. Can be provided multiple times.',
              multiple=True)
@click.option('-proto', '--protocol', 'inputProtocol',
              default='',
              help='Specifies which protocols parse.',
              multiple=True)
@click.option('-diff', '--diff-only', 'bDiffOnly',
              is_flag=True,
              help='Print only differeces.',
              default=False)
@click.argument('rtdump1', type=click.File('r'))
@click.argument('rtdump2', type=click.File('r'))
def compareRTs(inputVpnInstance, inputProtocol, bDiffOnly, rtdump1, rtdump2):
    """
        Comparison of routing table dump from 'rtdump1' file with dump from 'rtdump2' file.
        rtdump1 - is a TOBE-state of routing table.
        rtdump2 - is ASIS-state.
    """
    if gDebug:
        print '\tStart aruments:'
        for arg, val in locals().items():
            if type(val) is list:
                val = 'list with %s entries.' % len(val)
            click.echo('\t\t"%s" is "%s"' % (arg, val))

    allRoutingTablesAsis = parseRoutingTableHuaweiCE(rtdump2)
    allRoutingTablesTobe = parseRoutingTableHuaweiCE(rtdump1)

    #Preparations to Comparing - adding Tobe fields to Asis records.
    if gDebug >= 2:
        print 'Prepare to comparing RTs. ============================================================================================'

    for RT in allRoutingTablesAsis:
        vpnInstanceName = RT['Name']
        if gDebug >= 3:
            print '\t VPN-Instance: %s' % vpnInstanceName

        #get corresponding RouteRecords of Tobe-state
        RouteRecordsTobe = {}
        for RTT in allRoutingTablesTobe:
            if RTT['Name'] == vpnInstanceName:
                RouteRecordsTobe = RTT['RouteRecords']
                if gDebug >= 3:
                    print '\t Tobe-state info found for VPN-Instance %s' % RTT['Name']
                if gDebug >= 4:
                    print '\t\t RouteRecordsTobe: %s' %RouteRecordsTobe
                break

        for Prefix, Route in RT['RouteRecords'].items():
            try:
                ProtocolTobe = RouteRecordsTobe[Prefix]['Protocol']
                NexthopTobe = RouteRecordsTobe[Prefix]['Nexthop']
                InterfaceTobe = RouteRecordsTobe[Prefix]['Interface']

            except KeyError:
                if gDebug >= 3:
                    print '\t\t Tobe-state for Prefix %s not found.' % Prefix
                ProtocolTobe = ''
                NexthopTobe = ''
                InterfaceTobe = ''

            if gDebug >= 4:
                print '\t\t\tProtocolTobe=%s' % ProtocolTobe
                print '\t\t\tNexthopTobe=%s' % NexthopTobe
                print '\t\t\tInterfaceTobe=%s' % InterfaceTobe

            Route.update(
                {'ProtocolTobe': ProtocolTobe,
                 'NexthopTobe': NexthopTobe,
                 'InterfaceTobe': InterfaceTobe,
                }
            )
            if gDebug >= 4:
                print '\t\t Updated Route is: %s' % Route

    # Print 
    if gDebug >= 1:
        print '\n\n\n== PRINTING ==========================================='

    printComparedEntrypoint(allRoutingTablesAsis, outputFormat, inputVpnInstance, inputProtocol, bDiffOnly)

@cli.command()
@click.option('-vpn', '--vpn-instance', 'inputVpnInstance',
              default='',
              help='Parce only this one vpn-instance. Case sencetive. Can be provided multiple times.',
              multiple=True)
@click.option('-proto', '--protocol', 'inputProtocol',
              default='',
              help='Specifies which protocols parse. Case sencetive. Can be provided multiple times.',
              multiple=True)
@click.argument('rtdump', type=click.File('r'))
def parseRT(inputVpnInstance, inputProtocol, rtdump):
    """
        Parsing RTDUMP and printing it in specified format.
        rtdump - Dump of routing table Huawei CE12800 by 'display ip routing-table'.
    """
    if gDebug:
        print '\tparseRT start aruments:'
        for arg, val in locals().items():
            if type(val) is list:
                val = 'list with %s entries.' % len(val)
            click.echo('\t\t"%s" is "%s"' % (arg, val))

    allRoutingTables = parseRoutingTableHuaweiCE(rtdump)

    # Print 
    if gDebug >= 1:
        print '\n\n\n== PRINTING ==========================================='

    tobePrinted = []

    #filter records for printing
    for RT in allRoutingTables:
        #Skip this VPN if it not in filter-list, if filter-list not blank
        if (
            (RT['Name'] in inputVpnInstance) or
            (inputVpnInstance == ())
        ):
            if gDebug >= 3:
                click.echo('\t\tVPN-Instance %s is in filter-list. Add it to print list.' % RT['Name'])

            tobePrintedRTRRs = {}

            for rec, recval in RT['RouteRecords'].items():
                try:
                    #if Protocol or ProtocolTobe is not int specified Protocols, goto next.
                    if not (
                        (recval['Protocol'] in inputProtocol) or
                        ( inputProtocol == () )
                    ) :
                        continue

                    if gDebug >= 4:
                        click.echo('\t\t\tAdding RR "{0}" to printing queue.'.format([rec,recval]))

                    tobePrintedRTRRs.update({rec:recval})
                except KeyError:
                    if gDebug >= 4:
                        print '\t\t Recval: %s' % recval
                        raise
            #ENDFOR

            tobePrinted.append({'Name':RT['Name'],'RouteRecords':tobePrintedRTRRs})
        #ENDIF
    #ENDFOR

    printEntrypoint(tobePrinted, outputFormat)

if __name__ == '__main__':
    cli()

