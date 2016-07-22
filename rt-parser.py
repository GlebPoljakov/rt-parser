#!/usr/bin/env python

import sys

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


def parseRoutinTableHuaweiCE():
    inFile = sys.stdin

    allRoutingTables = []

    thisRTName = ''
    thisRTLines = []

    rtDelimiter = '------------------------------------------------------------------------------' # Line that delimits VPN-Instances in input

    lineCounter = -1

    while True:
        line = inFile.readline()
        # if it is an end of input, set line as rtDelimiter to invoke addition of routing info to allRoutingTables.
        if not line:
            line = rtDelimiter

        lineCounter = lineCounter + 1
        line = line.strip('\n\r')       # Strip linendings

        #print 'Current Line:%s \n\tHex: %s' % (line, str2hexstr(line))

        #Skip empty lines
        if line.strip() == '': continue

        # Is its new VPN-Instance Routing Table?
        if line == rtDelimiter:
            #append resulting RT-List with new instance of VPN and VPN routes, do it only if it is not a first iteration.
            if thisRTName != '':
                allRoutingTables.append({'Name': thisRTName, 'RouteRecords': thisRTLines })

            # Read new VPN-instance name
            line = sys.stdin.readline()
            #print '\tSearch for VPN-Name: "%s" and Hex: "%s"' % (line, str2hexstr(line))
            lineCounter = lineCounter + 1

            if 'Routing Table' not in line:
                print 'Could not parse input.'
                break

            thisRTName = line[16:].strip()
            thisRTLines = []

            #print 'New RT: %s' % thisRTName

            # Skip header lines
            for x in xrange(3):
                line = inFile.readline().strip()
                lineCounter = lineCounter + 1
                #print 'SKIP - Line: "%s" and Hex: "%s"' % (line, str2hexstr(line))

            lineCounter = lineCounter + 1
            continue

        #if it is first iteration and we didn't yet find VPN-Instance Name, search for it first.
        if thisRTName == '': continue

        # Else parse the record
        RouteLine = list(slices(line, 20, 8, 5, 11, 6, 16, 200))

        """
            Parse RecordLine to RouteRecord dict:
                RouteRecord = {
                                'Prefix': '10.1.1.0/24',
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
            #print 'Prefix is "%s"' % Prefix
            #Parse a RouteLine into a RouteRecord
            RouteRecord = {
                        'Prefix': Prefix,
                        'Protocol': RouteLine[1].strip(),
                        'Preference': RouteLine[2].strip(),
                        'Cost': RouteLine[3].strip(),
                        'Flags': RouteLine[4].strip(),
                        'Nexthop': [RouteLine[5].strip(),],
                        'Interface': [RouteLine[6].strip(),],
            }
            # Append a RouteRecord to routing table of VPN-Instance
            thisRTLines.append(RouteRecord)
        else:
            # this RouteLine is continue of previous, thus we need append info in this line into a previous RouteRecord
            try:
                thisRTLines[-1]['Nexthop'].append(RouteLine[5].strip())
                thisRTLines[-1]['Interface'].append(RouteLine[6].strip())
            except IndexError:
                print 'Current Line:%s \n\tHex: %s' % (line, str2hexstr(line))
                print 'Current RouteLine:%s \n\tHex: %s' % (RouteLine, str2hexstr(RouteLine))
                print 'Error on line %d' % lineCounter
                raise
                quit()

    # Print 
    printYAML = False

    if printYAML:
        import yaml
        print yaml.dump(allRoutingTables, default_flow_style=False)

    for RT in allRoutingTables:
        print 'VPN: %s \t\t Routes: %s' % (RT['Name'], len(RT['RouteRecords']))

        continue

        for line in RT['RouteRecords']:
            print '%s\t%s' % (line['Prefix'], line['Interface'])

    #print allRoutingTables

def main():
    parseRoutinTableHuaweiCE()


if __name__ == '__main__':
    main()

