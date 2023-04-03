from two_factor.plugins.registry import MethodRegistry, registry


# class CustomRegistry(MethodRegistry):
#     def get_method(self, method):
#         # Prevent the GeneratorMethod (TOTP) from being returned
#         if method == 'generator':
#             return None
#         return super().get_method(method)


from two_factor.forms import MethodForm
from django import forms
from django.utils.translation import gettext_lazy as _


class MethodForm1(MethodForm):
    method = forms.ChoiceField(label=_("Method"), widget=forms.RadioSelect)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        method = self.fields['method']
        # remove TOTP generator method from choices
        method.choices = [
            (m.code, m.verbose_name) for m in registry.get_methods()
            if m.code == 'email'
        ]
        method.initial = method.choices[0][0]
