static add_segment(start_addr, end_addr, name, sclass)
{
    AddSeg(start_addr, end_addr, 0, 1, 1, 2); // Create the segment
    RenameSeg(start_addr, name);              // Rename the segment
    SetSegmentType(start_addr, sclass);       // Set the segment class (CODE/DATA/IO)
    Message("Segment %s added from 0x%X to 0x%X\n", name, start_addr, end_addr);
}

// Segment classes in IDC:
// CODE = 2
// DATA = 3
// IO   = 4

add_segment(0x00000000, 0x0003FFFF, "I_ROM", 2);  // CODE segment
add_segment(0x00040000, 0x00FAFFFF, "EXT_MEM", 3); // DATA segment
add_segment(0x00FFB000, 0x00FFEBFF, "RAM", 3);    // DATA segment
add_segment(0x00FFEC00, 0x00FFFBFF, "EXT_RAM", 3); // DATA segment
add_segment(0x00FFEC00, 0x00FFEF3F, "IO1", 4);    // IO segment
add_segment(0x00FFF640, 0x00FFFF5F, "EXT_MEM2", 3); // DATA segment
add_segment(0x00FFFF60, 0x00FFFFBF, "IO2", 4);    // IO segment
add_segment(0x00FFFC00, 0x00FFFFFF, "RAM2", 3);   // DATA segment

// Optionally, run auto-analysis
auto_wait();
Message("All segments added and analysis completed.\n");
