"""
User-friendly guide system for Security Buddy
Makes security concepts accessible to non-technical users
"""

class SecurityExplainer:
    """Explain security concepts in simple, everyday language"""
    
    @staticmethod
    def explain_security_score(score):
        """Convert technical security score to user-friendly explanation"""
        explanations = {
            (90, 100): {
                'level': 'Eccellente',
                'emoji': '🛡️',
                'color': 'success',
                'simple_text': 'Il tuo sito è molto sicuro!',
                'detailed_text': 'Fantastico! Il tuo sito web ha ottime protezioni di sicurezza. I tuoi visitatori possono navigare in tranquillità.',
                'action_needed': 'Continua così! Controlla periodicamente per mantenere questo livello.'
            },
            (70, 89): {
                'level': 'Buono',
                'emoji': '✅',
                'color': 'info',
                'simple_text': 'Il tuo sito è abbastanza sicuro',
                'detailed_text': 'Il tuo sito ha buone protezioni di base. Ci sono alcuni piccoli miglioramenti che potresti fare.',
                'action_needed': 'Segui i nostri consigli per migliorare ulteriormente la sicurezza.'
            },
            (50, 69): {
                'level': 'Da migliorare',
                'emoji': '⚠️',
                'color': 'warning',
                'simple_text': 'Il tuo sito ha bisogno di attenzione',
                'detailed_text': 'Ci sono alcune cose importanti che potresti sistemare per proteggere meglio il tuo sito e i tuoi visitatori.',
                'action_needed': 'Ti consigliamo di seguire le nostre raccomandazioni il prima possibile.'
            },
            (0, 49): {
                'level': 'Attenzione richiesta',
                'emoji': '🚨',
                'color': 'danger',
                'simple_text': 'Il tuo sito ha seri problemi di sicurezza',
                'detailed_text': 'Il tuo sito ha importanti vulnerabilità che potrebbero mettere a rischio i tuoi dati e quelli dei visitatori.',
                'action_needed': 'È importante agire subito! Contatta il tuo sviluppatore web o fornitore di hosting.'
            }
        }
        
        for (min_score, max_score), explanation in explanations.items():
            if min_score <= score <= max_score:
                return explanation
        
        return explanations[(0, 49)]  # Fallback
    
    @staticmethod
    def explain_https_issue():
        """Explain HTTPS in simple terms"""
        return {
            'title': 'Cos\'è HTTPS?',
            'simple': 'HTTPS significa che i dati tra il tuo sito e i visitatori sono criptati (nascosti).',
            'analogy': '🔒 È come mettere le lettere in una busta sigillata invece di inviarle su cartoline aperte.',
            'why_important': 'Senza HTTPS, i malintenzionati potrebbero spiare le password e i dati personali dei tuoi visitatori.',
            'how_to_fix': 'Contatta il tuo fornitore di hosting e chiedi di attivare il "certificato SSL gratuito".',
            'urgency': 'high'
        }
    
    @staticmethod
    def explain_ssl_certificate():
        """Explain SSL certificates in simple terms"""
        return {
            'title': 'Cos\'è un Certificato SSL?',
            'simple': 'Un certificato SSL è come un documento d\'identità per il tuo sito web.',
            'analogy': '🆔 È come avere una carta d\'identità che prova che il tuo sito è davvero il tuo.',
            'why_important': 'Senza questo "documento", i browser avvisano i visitatori che il sito potrebbe non essere sicuro.',
            'how_to_fix': 'La maggior parte dei fornitori di hosting offre certificati SSL gratuiti. Chiedilo al tuo provider.',
            'urgency': 'high'
        }
    
    @staticmethod
    def explain_security_headers():
        """Explain security headers in simple terms"""
        return {
            'title': 'Cosa sono le Intestazioni di Sicurezza?',
            'simple': 'Sono istruzioni speciali che il tuo sito dà ai browser per proteggere i visitatori.',
            'analogy': '📋 È come dare una lista di regole di sicurezza a chi entra in casa tua.',
            'why_important': 'Queste regole proteggono da trucchi che i malintenzionati usano per rubare informazioni.',
            'how_to_fix': 'Il tuo sviluppatore web può aggiungere queste protezioni. Mostragli questo report.',
            'urgency': 'medium'
        }
    
    @staticmethod
    def get_simple_recommendations(issues):
        """Generate user-friendly recommendations"""
        recommendations = []
        
        if 'https' in issues:
            recommendations.append({
                'priority': '🔴 Alta',
                'title': 'Attiva HTTPS sul tuo sito',
                'what_to_do': 'Contatta il tuo fornitore di hosting e chiedi di attivare HTTPS',
                'why': 'Per proteggere i dati dei tuoi visitatori',
                'who_can_help': 'Il tuo fornitore di hosting o sviluppatore web',
                'estimated_time': '15-30 minuti'
            })
        
        if 'ssl' in issues:
            recommendations.append({
                'priority': '🔴 Alta',
                'title': 'Rinnova o sistema il certificato SSL',
                'what_to_do': 'Verifica con il tuo hosting che il certificato SSL sia valido',
                'why': 'Per evitare avvisi di "sito non sicuro" ai visitatori',
                'who_can_help': 'Il supporto tecnico del tuo hosting',
                'estimated_time': '10-20 minuti'
            })
        
        if 'headers' in issues:
            recommendations.append({
                'priority': '🟡 Media',
                'title': 'Aggiungi protezioni extra',
                'what_to_do': 'Chiedi al tuo sviluppatore di aggiungere "security headers"',
                'why': 'Per una protezione ancora maggiore contro gli attacchi',
                'who_can_help': 'Il tuo sviluppatore web',
                'estimated_time': '30-60 minuti'
            })
        
        return recommendations

class UserGuideTutorial:
    """Interactive tutorial system for first-time users"""
    
    @staticmethod
    def get_welcome_tutorial():
        """Get welcome tutorial steps"""
        return [
            {
                'step': 1,
                'title': 'Benvenuto in Security Buddy! 👋',
                'content': 'Ti aiuteremo a capire quanto è sicuro il tuo sito web in modo semplice.',
                'action': 'Iniziamo!',
                'highlight': '#scanForm'
            },
            {
                'step': 2,
                'title': 'Inserisci il tuo sito web',
                'content': 'Scrivi l\'indirizzo del tuo sito (esempio: miosito.com) nella casella qui sotto.',
                'action': 'Prova ora',
                'highlight': '#targetInput'
            },
            {
                'step': 3,
                'title': 'Avvia la scansione',
                'content': 'Clicca sul pulsante "Scansiona" e faremo tutti i controlli necessari per te.',
                'action': 'Perfetto!',
                'highlight': '#scanButton'
            },
            {
                'step': 4,
                'title': 'Leggi i risultati',
                'content': 'Ti mostreremo tutto in parole semplici, con consigli pratici su cosa fare.',
                'action': 'Ho capito',
                'highlight': '.check-section'
            }
        ]
    
    @staticmethod
    def get_dashboard_tutorial():
        """Get dashboard tutorial for logged users"""
        return [
            {
                'step': 1,
                'title': 'La tua dashboard personale 📊',
                'content': 'Qui puoi vedere tutti i siti che hai controllato e come stanno andando nel tempo.',
                'highlight': '.stat-card'
            },
            {
                'step': 2,
                'title': 'Cronologia delle scansioni',
                'content': 'Ogni scansione viene salvata qui. Puoi rivedere i risultati quando vuoi.',
                'highlight': '.table-responsive'
            },
            {
                'step': 3,
                'title': 'Funzioni Premium',
                'content': 'Con il piano Premium puoi scaricare report PDF e ricevere alert automatici.',
                'highlight': '.premium-cta'
            }
        ]

class SecurityGlossary:
    """Simple explanations of security terms"""
    
    terms = {
        'HTTPS': {
            'simple': 'Connessione sicura',
            'explanation': 'Quando vedi il lucchetto verde nella barra del browser, significa che la connessione è criptata.',
            'analogy': 'È come parlare in codice segreto che solo tu e il sito web capite.'
        },
        'SSL Certificate': {
            'simple': 'Carta d\'identità del sito',
            'explanation': 'Un documento digitale che prova che il sito web è autentico.',
            'analogy': 'Come la carta d\'identità di una persona, ma per i siti web.'
        },
        'Security Headers': {
            'simple': 'Regole di protezione',
            'explanation': 'Istruzioni che il sito dà al browser per proteggere meglio i visitatori.',
            'analogy': 'Come le regole di sicurezza in un edificio: "Non aprire questa porta", "Controllare l\'ID".'
        },
        'Vulnerability': {
            'simple': 'Punto debole',
            'explanation': 'Un problema che i malintenzionati potrebbero sfruttare per danneggiare il sito.',
            'analogy': 'Come una finestra rotta in casa: bisogna ripararla prima che qualcuno entri.'
        },
        'Firewall': {
            'simple': 'Guardia digitale',
            'explanation': 'Un sistema che blocca gli attacchi prima che raggiungano il tuo sito.',
            'analogy': 'Come un buttafuori che controlla chi può entrare in discoteca.'
        }
    }
    
    @classmethod
    def get_explanation(cls, term):
        """Get simple explanation for a security term"""
        return cls.terms.get(term, {
            'simple': 'Termine tecnico',
            'explanation': 'Un concetto di sicurezza informatica.',
            'analogy': 'Chiedi al tuo sviluppatore per maggiori dettagli.'
        })

class UserFriendlyFormatter:
    """Format technical data in user-friendly way"""
    
    @staticmethod
    def format_scan_time(scan_time):
        """Format scan time in friendly way"""
        from datetime import datetime
        try:
            scan_dt = datetime.fromisoformat(scan_time.replace('Z', '+00:00'))
            now = datetime.now(scan_dt.tzinfo)
            diff = now - scan_dt
            
            if diff.days > 0:
                return f"{diff.days} giorni fa"
            elif diff.seconds > 3600:
                hours = diff.seconds // 3600
                return f"{hours} ore fa"
            elif diff.seconds > 60:
                minutes = diff.seconds // 60
                return f"{minutes} minuti fa"
            else:
                return "Appena adesso"
        except:
            return "Poco fa"
    
    @staticmethod
    def format_issue_count(issues):
        """Format issue count in friendly way"""
        count = len(issues) if issues else 0
        if count == 0:
            return "Nessun problema trovato! 🎉"
        elif count == 1:
            return "1 cosa da sistemare"
        else:
            return f"{count} cose da sistemare"
    
    @staticmethod
    def get_encouragement_message(score):
        """Get encouraging message based on score"""
        if score >= 90:
            return "Fantastico! Il tuo sito è molto sicuro! 🌟"
        elif score >= 70:
            return "Ottimo lavoro! Solo qualche piccolo miglioramento! 👍"
        elif score >= 50:
            return "Buon inizio! Con qualche sistemazione sarà perfetto! 💪"
        else:
            return "Non preoccuparti, ti aiutiamo a sistemare tutto! 🚀"