import subnet_verify

def parse_ipv4_mask (ip_with_mask):
    split = ip_with_mask.split('/')
    if len(split) != 2 or (not subnet_verify.is_ipv4(split[0])):
        return None
    try:
        num_bit_mask = int(split[1])
        if num_bit_mask > 31 or num_bit_mask < 0:
            return None
        mask_bit = ''
        i = 0
        while i < 32:
            if i < num_bit_mask:
                mask_bit = mask_bit + '1'
            else:
                mask_bit = mask_bit + '0'
            i = i + 1
        for i in range(len(mask_bit))[::-1]:
            if i % 8 == 0 and i != 0:
                mask_bit = mask_bit[:i] + '.' + mask_bit[i:]
        mask_sub = []
        for i in mask_bit.split('.'):
            mask_sub = mask_sub + [int(i, 2)]
        mask = ''
        for i in range(len(mask_sub)):
            if i != 0:
                mask = mask + '.'
            mask = mask + str(mask_sub[i])
        return (split[0], mask)
    except:
        return None
