"""Evaluates the CloudFormation intrinsic functions used by the generated template."""


class Stack:
    def __init__(self, template, parameters, resource_refs):
        self.t = template
        self.params = {k: v.get("Default") for k, v in template["Parameters"].items()}
        self.params.update(parameters)
        for name, spec in template["Parameters"].items():
            if spec["Type"] == "CommaDelimitedList" and isinstance(self.params[name], str):
                self.params[name] = self.params[name].split(",")
        self.refs = resource_refs

    def condition(self, name):
        return self.eval(self.t["Conditions"][name])

    def exists(self, logical_id):
        cond = self.t["Resources"][logical_id].get("Condition")
        return cond is None or self.condition(cond)

    def eval(self, node):
        if isinstance(node, list):
            return [self.eval(v) for v in node]
        if not isinstance(node, dict):
            return node
        if len(node) == 1:
            (fn, arg), = node.items()
            if fn == "Ref":
                return self.params[arg] if arg in self.params else self.refs[arg]
            if fn == "Condition":
                return self.condition(arg)
            if fn == "Fn::If":
                return self.eval(arg[1] if self.condition(arg[0]) else arg[2])
            if fn == "Fn::Equals":
                return self.eval(arg[0]) == self.eval(arg[1])
            if fn == "Fn::Not":
                return not self.eval(arg[0])
            if fn == "Fn::And":
                return all(self.eval(a) for a in arg)
            if fn == "Fn::Or":
                return any(self.eval(a) for a in arg)
            if fn == "Fn::Join":
                return arg[0].join(self.eval(arg[1]))
            if fn == "Fn::Sub":
                out = arg
                for k, v in {**self.params, **self.refs}.items():
                    if isinstance(v, str):
                        out = out.replace("${" + k + "}", v)
                return out
            if fn == "Fn::GetAtt":
                return self.refs[".".join(arg)]
        return {k: self.eval(v) for k, v in node.items()}
