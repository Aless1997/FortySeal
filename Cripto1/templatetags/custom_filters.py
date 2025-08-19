from django import template

register = template.Library()

@register.filter(name='endswith')
def endswith(value, arg):
    """
    Verifica se una stringa termina con un determinato suffisso.
    Esempio d'uso: {{ value|endswith:'.jpg' }}
    """
    return str(value).endswith(arg)

@register.filter(name='get_item')
def get_item(dictionary, key):
    """
    Ottiene un elemento da un dizionario utilizzando la chiave fornita.
    Esempio d'uso: {{ my_dict|get_item:item_key }}
    """
    if dictionary is None:
        return None
    
    # Usa get con un valore di default (lista vuota) per le chiavi 'files'
    if key == 'files':
        return dictionary.get(key, [])
    
    # Per altre chiavi, restituisci None se la chiave non esiste
    return dictionary.get(key)