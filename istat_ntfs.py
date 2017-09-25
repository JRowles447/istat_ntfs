import struct
import datetime

def as_signed_le(bs):
    signed_format = {1: 'b', 2: 'h', 4: 'l', 8: 'q'}
    if len(bs) <= 0 or len(bs) > 8:
        raise ValueError()

    fill = b'\x00'
    if ((bs[-1] & 0x80) >> 7) == 1:
        fill = b'\xFF'

    while len(bs) not in signed_format:
        bs = bs + fill
    result = struct.unpack('<' + signed_format[len(bs)], bs)[0]
    return result

# added from istat_fat16
def as_unsigned(bs, endian='<'):
    unsigned_format = {1: 'B', 2: 'H', 4: 'L', 8: 'Q'}
    if len(bs) <= 0 or len(bs) > 8:
        raise ValueError()
    fill = '\x00'
    while len(bs) not in unsigned_format:
        bs = bs + fill
    result = struct.unpack(endian + unsigned_format[len(bs)], bs)[0]
    return result


def istat_ntfs(f, address, sector_size=512, offset=0):
    istat_result = []
    f.seek(offset*sector_size, 0)
    boot_sector = f.read(512)

    size_of_sector = as_signed_le(boot_sector[11:13])
    sectors_per_cluster = as_signed_le(boot_sector[13:14])
    starting_cluster_mft = as_signed_le(boot_sector[48:56])

    f.seek(offset*size_of_sector + starting_cluster_mft*sectors_per_cluster*size_of_sector, 0)
    f.seek(address*1024, 1)

    istat_result.append('MFT Entry Header Values: ')
    # TODO change the hardcode 1024 to entry num skipped
    master_file_table = f.read(1024)
    sequence_number = as_signed_le(master_file_table[16:18])
    istat_result.append('Entry: ' + str(address) + '        Sequence: ' + str(sequence_number))

    #TODO change the allocation
    istat_result.append('$LogFile Sequence Number: ' + str(as_signed_le(master_file_table[8:16])))
    if((master_file_table[22:24] and 0x0001) == 0x0001):
        istat_result.append('Allocated File')
    else:
        istat_result.append('Not Allocated')
    offset_to_attribute = as_signed_le(master_file_table[20:22])
    link_count = as_signed_le(master_file_table[18:20])
    istat_result.append('Links: ' + str(link_count))
    istat_result.append('')
    attribute_type_byte = master_file_table[offset_to_attribute:offset_to_attribute + 4]
    attribute_type = as_signed_le(attribute_type_byte)

    attribute_footer_ret_list = ['Attributes:']
    exit_count = 0

    while attribute_type_byte != 0xffffffff and exit_count < 4:
        resident_attribute = True
        #TODO add the resident nonresident difference
        if as_signed_le(master_file_table[offset_to_attribute+8: offset_to_attribute+9]) == 1:
            resident_attribute = False
        does_it_matter = False
        if (attribute_type == 16) or (attribute_type == 32) or (attribute_type == 48) or (attribute_type == 128):
            does_it_matter = True
        attribute_length = as_signed_le(master_file_table[offset_to_attribute+4:offset_to_attribute+8])
        attribute_content_offset = as_signed_le(master_file_table[offset_to_attribute+20: offset_to_attribute+22])
        attribute_content_size = as_signed_le(master_file_table[offset_to_attribute+16: offset_to_attribute+20])
        attribute_unique_id = as_signed_le(master_file_table[offset_to_attribute+14:offset_to_attribute+16])


        if does_it_matter:
            if attribute_type == 16:
                std_info_content = master_file_table[offset_to_attribute + attribute_content_offset: offset_to_attribute + attribute_content_offset+ attribute_content_size+1]
                std_parsed_attribute = parse_std_info(std_info_content)
                # check the resident status
                if resident_attribute:
                    attribute_footer_ret_list.append('Type: $STANDARD_INFORMATION (16-' + str(attribute_unique_id) + ')   Name: N/A   Resident   size: ' + str(attribute_content_size))
                else:
                    attribute_footer_ret_list.append('Type: $STANDARD_INFORMATION (16-' + str(attribute_unique_id) + ')   Name: N/A   Non-Resident   size: ' + str(attribute_content_size))
                for x in std_parsed_attribute:
                    istat_result.append(x)
            if attribute_type == 48:
                file_name_content = master_file_table[offset_to_attribute + attribute_content_offset: offset_to_attribute + attribute_content_offset + attribute_content_size+1]

                file_parsed_attribute = parse_file_name(file_name_content)
                #TODO make a method to do footer parsing
                if resident_attribute:
                    attribute_footer_ret_list.append('Type: $FILE_NAME (48-' + str(attribute_unique_id) + ')   Name: N/A   Resident   size: ' + str(attribute_content_size))
                else:
                    attribute_footer_ret_list.append('Type: $FILE_NAME (48-' + str(attribute_unique_id) + ')   Name: N/A   Non-Resident   size: ' + str(attribute_content_size))
                for x in file_parsed_attribute:
                    istat_result.append(x)
            if attribute_type == 128:
                data_content = master_file_table[offset_to_attribute + attribute_content_offset: offset_to_attribute + attribute_length+2]
                print('$DATA content: ' + str(data_content))
                #TODO CHECK THAT THE FLAG IS ACCESSED CORRECTLY
                if not resident_attribute:
                    data = parse_non_resident_data(data_content)
                    print("continues")
                    size_of_attribute = as_unsigned(data_content[40:48])
                    size_of_attribute_init = as_unsigned(data_content[48:56])
                    footer_temp = []
                    y = 0
                    iterations = len(data) // 8
                    while (y < (iterations)):
                        footer_temp.append(' '.join(data[y * 8:((y + 1) * 8)]))
                        y += 1
                    if (len(data) % 8 != 0):
                        footer_temp.append(' '.join(data[y * 8:]))
                    #TODO fix the hard coding thats happening here!
                    footer_string_corrected = (''.join(footer_temp))
                    print('before the formatting')
                    # use size_of_attribute for the actual clusters
                    attribute_footer_ret_list.append('Type: $DATA (128-'+str(attribute_unique_id)+')   Name: N/A   Non-Resident   size: ' + str(size_of_attribute_init)+'  init_size: ' + str(size_of_attribute_init) + '\n')
                    for x in footer_temp:
                        attribute_footer_ret_list.append(x)
                else:
                    size_of_attribute = as_unsigned(data_content[16:20])
                    attribute_footer_ret_list.append('Type: $DATA (128-'+str(attribute_unique_id)+')   Name: N/A   Resident   size: ' + str(attribute_content_size))

        offset_to_attribute += attribute_length
        attribute_type_byte = master_file_table[offset_to_attribute:offset_to_attribute + 4]
        attribute_type = as_signed_le(attribute_type_byte)
        exit_count += 1
    for x in attribute_footer_ret_list:
        istat_result.append(x)










    #TODO add the $DATA parse method
    # istat_result.append('type: ' + str(attribute_type))
    # istat_result.append('length: ' + str(attribute_length))
    # print('the list is ' + str(istat_result))
    return istat_result

def parse_std_info(bytes):
    return_list = []
    flag_string = get_flag_values(as_signed_le(bytes[32:36]))
    return_list.append('$STANDARD_INFORMATION Attribute Values: ')
    return_list.append('Flags: ' + flag_string)
    owner_id = as_signed_le(bytes[48:52])
    # security_id = as_signed_le(bytes[52:56])

    #MARC said to hard code to zero
    return_list.append('Owner ID: ' + str(0))
    # Marc told us not to include security id
    # return_list.append('Security ID: ' + str(security_id) + ' ()')

    #time parsing
    time_list = get_attribute_times(bytes[0:32])
    for x in time_list:
        return_list.append(x)
    return_list.append('')
    return return_list

def parse_file_name(bytes):
    return_list = []
    return_list.append('$FILE_NAME Attribute Values: ')
    flag_string = get_flag_values(as_signed_le(bytes[56:60]))
    return_list.append('Flags: ' + flag_string)

    # name information
    length_name = as_signed_le(bytes[64:65])
    name_value = (bytes[66:66+length_name*2]).decode('utf-16') #is this correct?
    return_list.append('Name: ' + str(name_value))

    file_reference_sequence = as_signed_le(bytes[6:8]) #sequence of the parent directory
    file_reference_mft_entry = as_signed_le(bytes[0:6]) #entry number of the parent directory
    return_list.append('Parent MFT Entry: ' + str(file_reference_mft_entry) + ' \tSequence: ' + str(file_reference_sequence))
    allocated_size = as_signed_le(bytes[40:48])
    actual_size = as_signed_le(bytes[48:56])
    return_list.append('Allocated Size: ' + str(allocated_size) + '   \tActual Size: ' + str(actual_size))
    time_list = get_attribute_times(bytes[8:40])
    for x in time_list:
        return_list.append(x)
    return_list.append('')
    return return_list


def parse_non_resident_data(bytes):
    return_list = []
    starting_vcn = as_signed_le(bytes[16:24]) #signed?
    ending_vcn = as_signed_le(bytes[24:32])
    offset_to_runlist = as_signed_le(bytes[32:34])
    runlist_bytes = bytes[offset_to_runlist:]
    runlist_clusters = read_runlist(runlist_bytes)
    allocated_size = as_signed_le(bytes[40:48])
    actual_size = as_signed_le(bytes[48:56])
    print('before the loop')
    for x in runlist_clusters:
        return_list.append(x)
    print('finished the return_list')
    return return_list

def read_runlist(bytes):
    list_of_clusters = []

    #index is the start of the data! keep track!!!
    index = 1
    old_offset = 0
    while bytes[index-1] != 0x00:
        run_length_byte_length = as_signed_le((bytes[index-1] & 0xf).to_bytes(1, 'little'))
        offset_byte_length = as_unsigned(((bytes[index-1] & 0xf0) >> 4).to_bytes(1, 'little'))
        print('Entire run list is: \n' + str(bytes) + '\n')
        print("first byte is: " + str(bytes[0]))
        print(str(offset_byte_length) + " bytes for offset value")
        print(str(run_length_byte_length) + " bytes for length value")

        #358 highlighted orange
        length_of_run = as_unsigned(bytes[index: index+ run_length_byte_length])
        #reading inthe run offset
        print("the length of cluster run offset is " + str(index+run_length_byte_length) +" - " + str(index + run_length_byte_length + offset_byte_length))
        cluster_run_offset = as_signed_le(bytes[index+run_length_byte_length: index + run_length_byte_length + offset_byte_length])
        print("cluster_run_offset is: " + str(cluster_run_offset))
        print("length of the run:" + str(length_of_run))
        #fake code
        counter = 0
        while counter < length_of_run:
            # print("cluster: " + str(cluster_run_offset + counter))
            list_of_clusters.append(str(cluster_run_offset + old_offset+ counter))
            counter += 1
        index += run_length_byte_length + offset_byte_length+1
        old_offset += cluster_run_offset
    print("done execution")
    return list_of_clusters

def get_flag_values(flag_byte):
    flag_list = []
    if ((flag_byte & 0x0001) == 0x0001):
        flag_list.append('Read Only')
    if ((flag_byte & 0x0002) == 0x0002):
        flag_list.append('Hidden')
    if ((flag_byte & 0x0004) == 0x0004):
        flag_list.append('System')
    if ((flag_byte & 0x0020) == 0x0020):
        flag_list.append('Archive')
    if ((flag_byte & 0x0040) == 0x0040):
        flag_list.append('Device')
    if ((flag_byte & 0x0080) == 0x0080):
        flag_list.append('Normal')
    if ((flag_byte & 0x0100) == 0x0100):
        flag_list.append('Temporary')
    if ((flag_byte & 0x0200) == 0x0200):
        flag_list.append('Sparse file')
    if ((flag_byte & 0x0400) == 0x0400):
        flag_list.append('Reparse point')
    if ((flag_byte & 0x0800) == 0x0800):
        flag_list.append('Compressed')
    if ((flag_byte & 0x1000) == 0x1000):
        flag_list.append('Offline')
    if ((flag_byte & 0x2000) == 0x2000):
        flag_list.append('Content is not being indexed for faster searches')
    if ((flag_byte & 0x4000) == 0x4000):
        flag_list.append('Encrypted')
    flag_string = ', '.join(flag_list)
    return flag_string

def get_attribute_times(bytes):
    time_list = []
    time_list.append('Created:\t' + str(into_localtime_string(as_unsigned(bytes[0:8]))))
    time_list.append('File Modified:\t' + str(into_localtime_string(as_unsigned(bytes[8:16]))))
    time_list.append('MFT Modified:\t' + str(into_localtime_string(as_unsigned(bytes[16:24]))))
    time_list.append('Accessed:\t' + str(into_localtime_string(as_unsigned(bytes[24:32]))))
    #
    # time_list.append('Created:\t' + str(0))
    # time_list.append('File Modified:\t' + str(0))
    # time_list.append('MFT Modified:\t' + str(0))
    # time_list.append('Accessed:\t' + str(0))
    return time_list

def into_localtime_string(windows_timestamp):
    """
    Convert a windows timestamp into istat-compatible output.

    Assumes your local host is in the EDT timezone.

    :param windows_timestamp: the struct.decoded 8-byte windows timestamp
    :return: an istat-compatible string representation of this time in EDT
    """
    dt = datetime.datetime.fromtimestamp((windows_timestamp - 116444736000000000) / 10000000)
    hms = dt.strftime('%Y-%m-%d %H:%M:%S')
    fraction = windows_timestamp % 10000000
    return hms + '.' + str(fraction) + '00 (EDT)'


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='Display details of a meta-data structure (i.e. inode).')
    parser.add_argument('-o', type=int, default=0, metavar='imgoffset',
                        help='The offset of the file system in the image (in sectors)')
    parser.add_argument('-b', type=int, default=512, metavar='dev_sector_size',
                        help='The size (in bytes) of the device sectors')
    parser.add_argument('image', help='Path to an NTFS raw (dd) image')
    parser.add_argument('address', type=int, help='Meta-data number to display stats on')
    args = parser.parse_args()
    with open(args.image, 'rb') as f:
        result = istat_ntfs(f, args.address, args.b, args.o)
        for line in result:
            print(line.strip())