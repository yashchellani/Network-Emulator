class Firewall:
  def __init__(self, *args):
    """
    Initializes the Firewall with a list of filtering rules.
    Each rule is a dictionary specifying what action to take (allow or block) for given conditions.
    """
    self.rules = args[0] if args else []

  def apply_rules(self, packet):
    """
    Checks an incoming packet against the firewall rules to decide whether to allow or block.
    """
    for rule in self.rules:
        if self._matches_rule(packet, rule):
            return rule['action'] 
    return 'allow' 

  def matches_rule(self, packet, rule):
    """
    Checks if a packet matches a specific rule.
    """
    for key, value in rule['conditions'].items():
        if packet.get(key) != value:
            return False
    return True

  def add_rule(self, action, conditions):
    """
    Adds a new rule to the firewall.
    """
    new_rule = {"id": len(self.rules) + 1, "action": action, "conditions": conditions}
    self.rules.append(new_rule)
    print(f"\nAdded rule: {self.rules[-1]}")

  def remove_rule(self, index):
    """
    Removes a rule from the firewall based on its index in the list.
    """
    if index < len(self.rules):
        del self.rules[index]
  
  def is_mac_blocked(self, mac):
    """
    Checks if there is a block rule for a specific IP address.
    """
    print(f"Checking if MAC {mac} is blocked...")
    for rule in self.rules:
      conditions = rule.get('conditions', {})
      if rule.get('action') == 'block' and ('mac' in conditions and conditions['mac'] == mac):
        return True
    return False