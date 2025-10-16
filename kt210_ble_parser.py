#!/usr/bin/env python3
"""
EcoFlow Wave 2 (KT210) BLE Packet Parser

This parser decodes BLE packets from the EcoFlow Wave 2 device.
Packets are 108 bytes long and contain device status information.
"""

import struct
from typing import Dict, Optional, Any


class KT210BleParser:
    """Parser for KT210 BLE packets (108 bytes)"""

    PACKET_LENGTH = 108

    # Field definitions: (name, byte_size, type)
    # Types: 'int' (little-endian int), 'float' (little-endian float), 'str' (UTF-8 string)
    FIELDS = [
        ('mode', 1, 'int'),
        ('sub_mode', 1, 'int'),
        ('set_temp', 1, 'int'),
        ('fan_value', 1, 'int'),
        ('env_temp', 4, 'float'),
        ('temp_sys', 1, 'int'),
        ('display_idle_time', 2, 'int'),
        ('display_idle_mode', 1, 'int'),
        ('time_en', 1, 'int'),
        ('time_set_val', 2, 'int'),
        ('time_remain_val', 2, 'int'),
        ('beep_enable', 1, 'int'),
        ('err_code', 4, 'int'),
        ('name', 32, 'str'),
        ('ref_en', 1, 'int'),
        ('bms_pid', 2, 'int'),
        ('wte_fth_en', 1, 'int'),
        ('temp_display', 1, 'int'),
        ('power_mode', 1, 'int'),
        ('power_src', 1, 'int'),
        ('psdr_pwr_watt', 2, 'signed_int'),  # Signed with endian swap
        ('bat_pwr_watt', 2, 'signed_int'),   # Signed with endian swap
        ('mptt_pwr_watt', 2, 'signed_int'),  # Signed with endian swap
        ('bat_dsg_remain_time', 4, 'int'),
        ('bat_chg_remain_time', 4, 'int'),
        ('bat_soc', 1, 'int'),
        ('bat_chg_status', 1, 'int'),
        ('out_let_temp', 4, 'float'),
        ('mppt_work', 1, 'int'),
        ('bms_err', 1, 'int'),
        ('rgb_state', 1, 'int'),
        ('water_value', 1, 'int'),
        ('bms_bound_flag', 1, 'int'),
        ('bms_undervoltage', 1, 'int'),
        ('ver', 1, 'int'),
        ('resv_u8', 20, 'raw'),  # Reserved bytes
    ]

    @staticmethod
    def bytes_to_int_little_endian(data: bytes) -> int:
        """Convert bytes to unsigned integer (little-endian)"""
        if len(data) == 1:
            return data[0] & 0xFF
        elif len(data) == 2:
            return (data[0] & 0xFF) + ((data[1] & 0xFF) << 8)
        elif len(data) == 4:
            return ((data[3] & 0xFF) << 24) | (data[0] & 0xFF) | \
                   ((data[1] & 0xFF) << 8) | ((data[2] & 0xFF) << 16)
        return 0

    @staticmethod
    def bytes_to_float_le_safe(data: bytes) -> float:
        """Convert bytes to float (little-endian), returning 0.0 for NaN/Inf"""
        if len(data) != 4:
            return 0.0

        # Convert bytes to int (little-endian), then to float
        int_val = KT210BleParser.bytes_to_int_little_endian(data)

        try:
            # Reinterpret int as float bits
            float_val = struct.unpack('f', struct.pack('I', int_val))[0]

            # Check for NaN or Inf
            if float_val != float_val or float_val == float('inf') or float_val == float('-inf'):
                return 0.0

            return float_val
        except:
            return 0.0

    @staticmethod
    def swap_endian_and_parse_signed_int(data: bytes) -> int:
        """
        Swap endian and parse as signed int (for power values).
        This mimics the Java swapEndianAndParseSignedInt method.
        """
        if len(data) < 2:
            return 0

        # Swap bytes
        swapped = bytes([data[1], data[0]])

        # Convert to hex string
        hex_str = swapped.hex().upper()

        if len(hex_str) == 4:
            # Check if first hex digit < 8 (positive)
            first_digit = int(hex_str[0], 16)
            if first_digit < 8:
                return int(hex_str, 16)
            else:
                # Negative number - extend sign
                return int.from_bytes(bytes.fromhex('FFFF' + hex_str),
                                     byteorder='big', signed=True)

        return 0

    @staticmethod
    def parse(data: bytes) -> Optional[Dict[str, Any]]:
        """
        Parse a BLE packet into a dictionary of field values.

        Args:
            data: Raw packet data (should be 108 bytes)

        Returns:
            Dictionary with parsed fields, or None if invalid packet
        """
        if data is None or len(data) < KT210BleParser.PACKET_LENGTH:
            return None

        result = {}
        offset = 0

        try:
            for field_name, field_size, field_type in KT210BleParser.FIELDS:
                # Extract bytes for this field
                field_data = data[offset:offset + field_size]

                # Parse based on type
                if field_type == 'int':
                    result[field_name] = KT210BleParser.bytes_to_int_little_endian(field_data)
                elif field_type == 'float':
                    result[field_name] = KT210BleParser.bytes_to_float_le_safe(field_data)
                elif field_type == 'signed_int':
                    result[field_name] = KT210BleParser.swap_endian_and_parse_signed_int(field_data)
                elif field_type == 'str':
                    # Decode as UTF-8, removing null bytes
                    try:
                        result[field_name] = field_data.decode('utf-8').rstrip('\x00')
                    except:
                        result[field_name] = ''
                elif field_type == 'raw':
                    result[field_name] = field_data

                offset += field_size

            return result

        except Exception as e:
            print(f"Error parsing packet: {e}")
            return None

    @staticmethod
    def format_output(parsed_data: Dict[str, Any]) -> str:
        """Format parsed data as a readable string"""
        if not parsed_data:
            return "Invalid data"

        lines = ["=== EcoFlow Wave 2 Status ==="]

        # Group related fields
        lines.append("\n[Mode & Temperature]")
        lines.append(f"  Mode: {parsed_data.get('mode', 'N/A')}")
        lines.append(f"  Sub Mode: {parsed_data.get('sub_mode', 'N/A')}")
        lines.append(f"  Set Temperature: {parsed_data.get('set_temp', 'N/A')}")
        lines.append(f"  Environment Temperature: {parsed_data.get('env_temp', 0.0):.2f}°")
        lines.append(f"  Outlet Temperature: {parsed_data.get('out_let_temp', 0.0):.2f}°")
        lines.append(f"  Temperature System: {parsed_data.get('temp_sys', 'N/A')}")
        lines.append(f"  Temperature Display: {parsed_data.get('temp_display', 'N/A')}")

        lines.append("\n[Fan & Control]")
        lines.append(f"  Fan Value: {parsed_data.get('fan_value', 'N/A')}")
        lines.append(f"  Beep Enable: {parsed_data.get('beep_enable', 'N/A')}")
        lines.append(f"  Display Idle Time: {parsed_data.get('display_idle_time', 'N/A')}")
        lines.append(f"  Display Idle Mode: {parsed_data.get('display_idle_mode', 'N/A')}")

        lines.append("\n[Timer]")
        lines.append(f"  Timer Enable: {parsed_data.get('time_en', 'N/A')}")
        lines.append(f"  Timer Set Value: {parsed_data.get('time_set_val', 'N/A')}")
        lines.append(f"  Timer Remain Value: {parsed_data.get('time_remain_val', 'N/A')}")

        lines.append("\n[Power]")
        lines.append(f"  Power Mode: {parsed_data.get('power_mode', 'N/A')}")
        lines.append(f"  Power Source: {parsed_data.get('power_src', 'N/A')}")
        lines.append(f"  PSDR Power: {parsed_data.get('psdr_pwr_watt', 'N/A')} W")
        lines.append(f"  Battery Power: {parsed_data.get('bat_pwr_watt', 'N/A')} W")
        lines.append(f"  MPPT Power: {parsed_data.get('mptt_pwr_watt', 'N/A')} W")
        lines.append(f"  MPPT Work: {parsed_data.get('mppt_work', 'N/A')}")

        lines.append("\n[Battery]")
        lines.append(f"  Battery SOC: {parsed_data.get('bat_soc', 'N/A')}%")
        lines.append(f"  Battery Charge Status: {parsed_data.get('bat_chg_status', 'N/A')}")
        lines.append(f"  Battery Discharge Remain Time: {parsed_data.get('bat_dsg_remain_time', 'N/A')} min")
        lines.append(f"  Battery Charge Remain Time: {parsed_data.get('bat_chg_remain_time', 'N/A')} min")

        lines.append("\n[BMS & Errors]")
        lines.append(f"  BMS PID: {parsed_data.get('bms_pid', 'N/A')}")
        lines.append(f"  BMS Error: {parsed_data.get('bms_err', 'N/A')}")
        lines.append(f"  BMS Bound Flag: {parsed_data.get('bms_bound_flag', 'N/A')}")
        lines.append(f"  BMS Undervoltage: {parsed_data.get('bms_undervoltage', 'N/A')}")
        lines.append(f"  Error Code: {parsed_data.get('err_code', 'N/A')}")

        lines.append("\n[Other]")
        lines.append(f"  Name: {parsed_data.get('name', 'N/A')}")
        lines.append(f"  Refrigeration Enable: {parsed_data.get('ref_en', 'N/A')}")
        lines.append(f"  Water Filter Enable: {parsed_data.get('wte_fth_en', 'N/A')}")
        lines.append(f"  RGB State: {parsed_data.get('rgb_state', 'N/A')}")
        lines.append(f"  Water Value: {parsed_data.get('water_value', 'N/A')}")
        lines.append(f"  Version: {parsed_data.get('ver', 'N/A')}")

        return '\n'.join(lines)


def main():
    """Example usage and test"""
    import sys

    # Example: Read hex string from command line or test data
    if len(sys.argv) > 1:
        # Parse hex string from command line
        hex_data = sys.argv[1].replace(' ', '').replace('0x', '')
        data = bytes.fromhex(hex_data)
    else:
        # Test with dummy data (108 bytes of zeros for testing structure)
        print("No data provided. Use: python kt210_ble_parser.py <hex_string>")
        print("Example: python kt210_ble_parser.py 01020304...")
        print("\nTesting with dummy data:\n")
        data = bytes(108)

    # Parse the data
    parsed = KT210BleParser.parse(data)

    if parsed:
        # Print formatted output
        print(KT210BleParser.format_output(parsed))

        # Also print raw dictionary for debugging
        print("\n=== Raw Parsed Data ===")
        for key, value in parsed.items():
            if key != 'resv_u8':  # Skip reserved bytes
                print(f"{key}: {value}")
    else:
        print("Failed to parse packet")


if __name__ == '__main__':
    main()

import struct


def parse_mh200_device_data(data: bytes) -> dict:
    """
    Parse EcoFlow Wave 2 (MH200) device data from BLE byte array.

    Args:
        data: Byte array of at least 83 bytes

    Returns:
        Dictionary containing parsed device status and power data
    """
    if data is None or len(data) < 83:
        raise ValueError(f"Invalid data length: {len(data) if data else 0}, expected at least 83 bytes")

    print(data)
    # Parse Status Data
    status_data = {
        'mode': data[0],  # signed byte
        'set_temp': data[1],  # unsigned byte
        'set_mode_value': data[2],
        'cur_temp': KT210BleParser.bytes_to_float_le_safe(data[3:6]), # float, little endian
        'temp_mode': data[7],  # signed byte
        'display_time': KT210BleParser.bytes_to_int_little_endian(data[8:9]),  # unsigned short, little endian
        'display_mode': KT210BleParser.bytes_to_int_little_endian(data[10:11]),  # unsigned short, little endian
        'timing': data[12] == 1,  # boolean
        'timing_set_value': KT210BleParser.bytes_to_int_little_endian( data[13:14]),  # unsigned short, little endian
        'timing_remain': KT210BleParser.bytes_to_int_little_endian(data[15:16]),  # unsigned short, little endian
        'beep': data[17] == 1,  # boolean
        'error_code': KT210BleParser.bytes_to_int_little_endian(data[18:21]),  # unsigned int, little endian
        'device_name': data[22:53].decode('utf-8', errors='ignore').strip('\x00').strip(),  # 32 bytes string
        'ref_en_bt': data[54] == 1,  # unsigned byte
        'bms_pid': KT210BleParser.bytes_to_int_little_endian(data[55:56]),  # unsigned short, little endian
        'wte_fth_en': data[57],  # unsigned byte
        'ref_mode': data[58],  # unsigned byte
        'power_mode': data[59],  # unsigned byte
        'ref_mode_val': data[60],  # unsigned byte
        # 'ref_cal_time': struct.unpack('<H', data[61:63])[0],  # unsigned short, little endian
        'eco_temp': data[63],  # unsigned byte
    }

    # Parse Power Data
    power_data = {
        'power_src': struct.unpack('b', data[66:67])[0],  # signed byte
        'power_watt': struct.unpack('<H', data[67:69])[0],  # unsigned short, little endian
        'battery_watt': struct.unpack('<h', data[69:71])[0],  # signed short, little endian
        'mptt_watt': struct.unpack('<H', data[71:73])[0],  # unsigned short, little endian
        'battery_dis_charge_time': struct.unpack('<I', data[73:77])[0],  # unsigned int, little endian
        'battery_charge_time': struct.unpack('<I', data[77:81])[0],  # unsigned int, little endian
        'battery_soc': data[81],  # unsigned byte
        'battery_status': data[82],  # unsigned byte
    }

    return {
        'status_data': status_data,
        'power_data': power_data
    }