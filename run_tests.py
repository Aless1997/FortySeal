#!/usr/bin/env python
"""
Advanced Django Test Runner
Script avanzato per l'esecuzione dei test Django con reporting completo
"""

import os
import sys
import django
import time
import json
from datetime import datetime
from django.conf import settings
from django.test.utils import get_runner
from django.core.management import execute_from_command_line
from io import StringIO
import subprocess

class AdvancedTestRunner:
    def __init__(self):
        self.start_time = None
        self.end_time = None
        self.results = {
            'timestamp': datetime.now().isoformat(),
            'tests_run': 0,
            'failures': 0,
            'errors': 0,
            'skipped': 0,
            'success_rate': 0.0,
            'execution_time': 0.0,
            'coverage_report': {},
            'detailed_results': [],
            'environment_info': {}
        }
        self.log_file = 'test_results.txt'
        self.json_file = 'test_results.json'
        
    def setup_environment(self):
        """Configura l'ambiente Django per i test"""
        os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'Cripto.settings')
        django.setup()
        
        # Raccoglie informazioni sull'ambiente
        self.results['environment_info'] = {
            'python_version': sys.version,
            'django_version': django.get_version(),
            'settings_module': os.environ.get('DJANGO_SETTINGS_MODULE'),
            'debug_mode': getattr(settings, 'DEBUG', False),
            'database_engine': settings.DATABASES['default']['ENGINE'],
            'installed_apps': list(settings.INSTALLED_APPS)
        }
        
    def run_coverage_analysis(self):
        """Esegue l'analisi della copertura del codice"""
        try:
            # Installa coverage se non presente
            subprocess.run([sys.executable, '-m', 'pip', 'install', 'coverage'], 
                         capture_output=True, check=False)
            
            # Esegue i test con coverage
            coverage_cmd = [
                sys.executable, '-m', 'coverage', 'run', 
                '--source=.', 'manage.py', 'test', 'Cripto1.tests'
            ]
            
            result = subprocess.run(coverage_cmd, capture_output=True, text=True)
            
            # Genera report coverage
            report_cmd = [sys.executable, '-m', 'coverage', 'report', '--format=json']
            report_result = subprocess.run(report_cmd, capture_output=True, text=True)
            
            if report_result.returncode == 0:
                try:
                    coverage_data = json.loads(report_result.stdout)
                    self.results['coverage_report'] = {
                        'total_coverage': coverage_data.get('totals', {}).get('percent_covered', 0),
                        'files_covered': len(coverage_data.get('files', {})),
                        'lines_covered': coverage_data.get('totals', {}).get('covered_lines', 0),
                        'lines_total': coverage_data.get('totals', {}).get('num_statements', 0)
                    }
                except json.JSONDecodeError:
                    self.results['coverage_report'] = {'error': 'Failed to parse coverage report'}
            
        except Exception as e:
            self.results['coverage_report'] = {'error': f'Coverage analysis failed: {str(e)}'}
    
    def run_tests(self, test_labels=None):
        """Esegue i test Django con reporting avanzato"""
        if test_labels is None:
            test_labels = ['Cripto1.tests']
            
        self.start_time = time.time()
        
        try:
            # Configura il test runner
            TestRunner = get_runner(settings)
            test_runner = TestRunner(
                verbosity=2,
                interactive=False,
                keepdb=True,  # Mantiene il DB per test più veloci
                reverse=False,
                debug_mode=False
            )
            
            # Esegue i test
            failures = test_runner.run_tests(test_labels)
            
            # Raccoglie i risultati
            self.results['tests_run'] = test_runner.suite.countTestCases() if hasattr(test_runner, 'suite') else 0
            self.results['failures'] = failures
            
            # Calcola statistiche
            if self.results['tests_run'] > 0:
                self.results['success_rate'] = ((self.results['tests_run'] - failures) / self.results['tests_run']) * 100
            
            return failures
            
        except Exception as e:
            self.results['errors'] = 1
            self.results['detailed_results'].append({
                'type': 'CRITICAL_ERROR',
                'message': str(e),
                'timestamp': datetime.now().isoformat()
            })
            return 1
        
        finally:
            self.end_time = time.time()
            self.results['execution_time'] = self.end_time - self.start_time
    
    def run_specific_tests(self):
        """Esegue test specifici per moduli critici"""
        critical_tests = [
            'Cripto1.tests.test_models',
            'Cripto1.tests.test_views', 
            'Cripto1.tests.test_forms',
            'Cripto1.tests.test_security'
        ]
        
        for test_module in critical_tests:
            try:
                print(f"\n🧪 Eseguendo test per: {test_module}")
                result = subprocess.run([
                    sys.executable, 'manage.py', 'test', test_module, '-v', '2'
                ], capture_output=True, text=True, timeout=300)
                
                self.results['detailed_results'].append({
                    'module': test_module,
                    'returncode': result.returncode,
                    'stdout': result.stdout[-500:],  # Ultimi 500 caratteri
                    'stderr': result.stderr[-500:] if result.stderr else '',
                    'success': result.returncode == 0
                })
                
            except subprocess.TimeoutExpired:
                self.results['detailed_results'].append({
                    'module': test_module,
                    'error': 'Test timeout (>300s)',
                    'success': False
                })
            except Exception as e:
                self.results['detailed_results'].append({
                    'module': test_module,
                    'error': str(e),
                    'success': False
                })
    
    def generate_reports(self):
        """Genera report dettagliati in formato txt e JSON"""
        # Report testuale dettagliato
        report_content = f"""
═══════════════════════════════════════════════════════════════
                    DJANGO TEST EXECUTION REPORT
═══════════════════════════════════════════════════════════════

📅 Timestamp: {self.results['timestamp']}
⏱️  Tempo di esecuzione: {self.results['execution_time']:.2f} secondi

📊 STATISTICHE GENERALI:
   • Test eseguiti: {self.results['tests_run']}
   • Fallimenti: {self.results['failures']}
   • Errori: {self.results['errors']}
   • Saltati: {self.results['skipped']}
   • Tasso di successo: {self.results['success_rate']:.1f}%

🔍 COVERAGE ANALYSIS:
"""
        
        if 'error' not in self.results['coverage_report']:
            coverage = self.results['coverage_report']
            report_content += f"""
   • Copertura totale: {coverage.get('total_coverage', 0):.1f}%
   • File coperti: {coverage.get('files_covered', 0)}
   • Linee coperte: {coverage.get('lines_covered', 0)}/{coverage.get('lines_total', 0)}
"""
        else:
            report_content += f"   • Errore: {self.results['coverage_report']['error']}\n"
        
        report_content += "\n🧪 DETTAGLI TEST SPECIFICI:\n"
        for i, test_result in enumerate(self.results['detailed_results'], 1):
            status = "✅ PASS" if test_result.get('success', False) else "❌ FAIL"
            module = test_result.get('module', f'Test #{i}')
            report_content += f"   {i}. {module}: {status}\n"
            
            if 'error' in test_result:
                report_content += f"      Errore: {test_result['error']}\n"
        
        report_content += f"""

🖥️  INFORMAZIONI AMBIENTE:
   • Python: {self.results['environment_info']['python_version'].split()[0]}
   • Django: {self.results['environment_info']['django_version']}
   • Debug Mode: {self.results['environment_info']['debug_mode']}
   • Database: {self.results['environment_info']['database_engine']}

═══════════════════════════════════════════════════════════════
                        FINE REPORT
═══════════════════════════════════════════════════════════════
"""
        
        # Salva report testuale
        with open(self.log_file, 'w', encoding='utf-8') as f:
            f.write(report_content)
        
        # Salva report JSON
        with open(self.json_file, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)
        
        print(f"\n📄 Report salvati:")
        print(f"   • Dettagliato: {self.log_file}")
        print(f"   • JSON: {self.json_file}")
    
    def print_summary(self):
        """Stampa un riassunto colorato dei risultati"""
        print("\n" + "="*60)
        print("🎯 RIASSUNTO ESECUZIONE TEST")
        print("="*60)
        
        status_icon = "✅" if self.results['failures'] == 0 and self.results['errors'] == 0 else "❌"
        print(f"{status_icon} Status: {'SUCCESS' if self.results['failures'] == 0 else 'FAILED'}")
        print(f"⏱️  Tempo: {self.results['execution_time']:.2f}s")
        print(f"📊 Successo: {self.results['success_rate']:.1f}%")
        
        if 'total_coverage' in self.results['coverage_report']:
            coverage = self.results['coverage_report']['total_coverage']
            coverage_icon = "🟢" if coverage >= 80 else "🟡" if coverage >= 60 else "🔴"
            print(f"{coverage_icon} Coverage: {coverage:.1f}%")
        
        print("="*60)

def main():
    """Funzione principale"""
    print("🚀 Avvio Advanced Django Test Runner...")
    
    runner = AdvancedTestRunner()
    
    try:
        # Setup ambiente
        print("⚙️  Configurazione ambiente...")
        runner.setup_environment()
        
        # Esegue test principali
        print("🧪 Esecuzione test principali...")
        failures = runner.run_tests()
        
        # Esegue test specifici
        print("🔍 Esecuzione test specifici...")
        runner.run_specific_tests()
        
        # Analisi coverage
        print("📊 Analisi coverage...")
        runner.run_coverage_analysis()
        
        # Genera report
        print("📄 Generazione report...")
        runner.generate_reports()
        
        # Stampa riassunto
        runner.print_summary()
        
        return failures
        
    except KeyboardInterrupt:
        print("\n⚠️  Esecuzione interrotta dall'utente")
        return 1
    except Exception as e:
        print(f"\n💥 Errore critico: {e}")
        return 1

if __name__ == "__main__":
    exit_code = main()
    sys.exit(bool(exit_code))