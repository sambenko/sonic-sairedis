#include "SwitchVpp.h"

#include "meta/sai_serialize.h"

#include "swss/logger.h"

#include "vppxlate/SaiVppXlate.h"

using namespace saivs;

sai_status_t SwitchVpp::addNatEntry(
        _In_ const std::string &serializedObjectId,
        _In_ sai_object_id_t switch_id,
        _In_ uint32_t attr_count,
        _In_ const sai_attribute_t *attr_list)
{
    SWSS_LOG_ENTER();

    sai_nat_entry_t nat_entry;
    sai_deserialize_nat_entry(serializedObjectId, nat_entry);

    // Store the entry in object DB
    CHECK_STATUS(create_internal(SAI_OBJECT_TYPE_NAT_ENTRY, serializedObjectId,
                switch_id, attr_count, attr_list));

    // Determine NAT type from attributes
    sai_nat_type_t nat_type = SAI_NAT_TYPE_NONE;
    sai_ip4_t src_ip = 0;
    sai_ip4_t dst_ip = 0;
    uint16_t l4_src_port = 0;
    uint16_t l4_dst_port = 0;
    bool enable_packet_count = false;
    bool enable_byte_count = false;

    for (uint32_t i = 0; i < attr_count; i++)
    {
        switch (attr_list[i].id)
        {
            case SAI_NAT_ENTRY_ATTR_NAT_TYPE:
                nat_type = (sai_nat_type_t)attr_list[i].value.s32;
                break;
            case SAI_NAT_ENTRY_ATTR_SRC_IP:
                src_ip = attr_list[i].value.ip4;
                break;
            case SAI_NAT_ENTRY_ATTR_DST_IP:
                dst_ip = attr_list[i].value.ip4;
                break;
            case SAI_NAT_ENTRY_ATTR_L4_SRC_PORT:
                l4_src_port = attr_list[i].value.u16;
                break;
            case SAI_NAT_ENTRY_ATTR_L4_DST_PORT:
                l4_dst_port = attr_list[i].value.u16;
                break;
            case SAI_NAT_ENTRY_ATTR_ENABLE_PACKET_COUNT:
                enable_packet_count = attr_list[i].value.booldata;
                break;
            case SAI_NAT_ENTRY_ATTR_ENABLE_BYTE_COUNT:
                enable_byte_count = attr_list[i].value.booldata;
                break;
            default:
                break;
        }
    }

    SWSS_LOG_NOTICE("NAT entry create: type=%d, key src_ip=0x%x dst_ip=0x%x "
            "src_port=%u dst_port=%u, action src_ip=0x%x dst_ip=0x%x "
            "l4_src=%u l4_dst=%u",
            nat_type,
            nat_entry.data.key.src_ip, nat_entry.data.key.dst_ip,
            nat_entry.data.key.l4_src_port, nat_entry.data.key.l4_dst_port,
            src_ip, dst_ip, l4_src_port, l4_dst_port);

    // TODO: Call VPP nat44-ed binary APIs via xlate layer
    // return vpp_add_nat_entry(nat_type, &nat_entry, src_ip, dst_ip,
    //                          l4_src_port, l4_dst_port);

    return SAI_STATUS_SUCCESS;
}

sai_status_t SwitchVpp::removeNatEntry(
        _In_ const std::string &serializedObjectId)
{
    SWSS_LOG_ENTER();

    sai_nat_entry_t nat_entry;
    sai_deserialize_nat_entry(serializedObjectId, nat_entry);

    SWSS_LOG_NOTICE("NAT entry remove: src_ip=0x%x dst_ip=0x%x "
            "src_port=%u dst_port=%u",
            nat_entry.data.key.src_ip, nat_entry.data.key.dst_ip,
            nat_entry.data.key.l4_src_port, nat_entry.data.key.l4_dst_port);

    // TODO: Call VPP nat44-ed binary APIs to remove mapping
    // vpp_remove_nat_entry(&nat_entry);

    // Remove from object DB
    auto sid = serializedObjectId;
    return remove_internal(SAI_OBJECT_TYPE_NAT_ENTRY, sid);
}

sai_status_t SwitchVpp::setNatEntryAttribute(
        _In_ const std::string &serializedObjectId,
        _In_ const sai_attribute_t *attr)
{
    SWSS_LOG_ENTER();

    SWSS_LOG_NOTICE("NAT entry set attr: id=%d", attr->id);

    // TODO: Handle attribute updates (e.g. counter enable/disable)

    return SAI_STATUS_SUCCESS;
}