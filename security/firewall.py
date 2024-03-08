class Firewall:
  def __init__(self, rules=[]):
    """
    Initializes the Firewall with a list of filtering rules.
    Each rule is a dictionary specifying what action to take (allow or block) for given conditions.
    """
    self.rules = rules

  def apply_rules(self, packet):
    """
    Checks an incoming packet against the firewall rules to decide whether to allow or block.
    """
    for rule in self.rules:
        if self._matches_rule(packet, rule):
            return rule['action'] 
    return 'allow' 

  def _matches_rule(self, packet, rule):
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
    self.rules.append({'action': action, 'conditions': conditions})

  def remove_rule(self, index):
    """
    Removes a rule from the firewall based on its index in the list.
    """
    if index < len(self.rules):
        del self.rules[index]