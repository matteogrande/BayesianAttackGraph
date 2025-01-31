from pgmpy.models import BayesianNetwork
from pgmpy.factors.discrete import TabularCPD
from pgmpy.inference import VariableElimination

def analyze_model(model):
    inference = VariableElimination(model)
    
    # 1. Calcolo della probabilità non condizionata di compromissione dei PLC
    plc1_prob = inference.query(variables=["PLC 1"], show_progress=False)
    plc2_prob = inference.query(variables=["PLC 2"], show_progress=False)
    print("Probabilità non condizionata di compromissione dei PLC:")
    print(plc1_prob)
    print(plc2_prob)
    
    # 2. Variazione della probabilità dell'attaccante e impatto sui PLC
    print("\nEffetto della probabilità dell'Attacker sulla compromissione dei PLC:")
    attacker_evidence = {"Attacker": "Present"}
        
    plc1_given_attacker = inference.query(variables=["PLC 1"], evidence=attacker_evidence, show_progress=False)
    plc2_given_attacker = inference.query(variables=["PLC 2"], evidence=attacker_evidence, show_progress=False)
        
    print(f"\nP(Attacker=Present) = 0.6")
    print(plc1_given_attacker)
    print(plc2_given_attacker)
    
    # 3. Inferenza diagnostica: dato che un PLC è compromesso, qual è la probabilità che un firewall sia compromesso?
    print("\nInferenza diagnostica: probabilità che Firewall 3 sia compromesso dato che PLC 1 è compromesso")
    diagnostic_inference = inference.query(variables=["Firewall 3"], evidence={"PLC 1": "Breached"}, show_progress=False)
    print(diagnostic_inference)
    
    # 4. Inferenza causale: effetto della protezione di Firewall 2 sulla compromissione di PLC 1
    print("\nInferenza causale: impatto della protezione di Firewall 2 sulla compromissione di PLC 1")
    causal_inference = inference.query(variables=["PLC 1"], evidence={"Firewall 2": "Non-Breached"}, show_progress=False)
    print(causal_inference)
    
    return

def main():
    # Creazione del modello
    model = BayesianNetwork()

    # Aggiunta dei nodi
    nodes = ["Attacker","Firewall 1","Web Server",
            "Email Server","Authentication Server",
            "Business Server","Firewall 2","Application Server",
            "Historian","Firewall 3","Firewall 4",
            "Local HMI 1","Local HMI 2","PLC 1","PLC 2"]
    
    edges = [("Attacker","Firewall 1"),
             ("Firewall 1","Web Server"),
             ("Firewall 1","Email Server"),
             ("Web Server","Authentication Server"),
             ("Web Server","Business Server"),
             ("Email Server","Authentication Server"),
             ("Email Server","Business Server"),
             ("Authentication Server","Firewall 2"),
             ("Business Server","Firewall 2"),
             ("Firewall 2","Application Server"),
             ("Firewall 2","Historian"),
             ("Application Server","Firewall 3"),
             ("Application Server","Firewall 4"),
             ("Historian","Firewall 3"),
             ("Historian","Firewall 4"),
             ("Firewall 3","Local HMI 1"),
             ("Firewall 4","Local HMI 2"),
             ("Local HMI 1","PLC 1"),
             ("Local HMI 2","PLC 2")]
    
    # Aggiunta dei nodi e degli archi al modello
    model.add_nodes_from(nodes)
    model.add_edges_from(edges)

    # Attacker (senza genitori)
    cpd_attacker = TabularCPD(
        variable="Attacker",
        variable_card=2,
        values=[
            [0.40],  # Attacker=0 (Absent)
            [0.60]   # Attacker=1 (Present)
        ],
        state_names={"Attacker": ["Absent", "Present"]}
    )

    # Firewall 1 (dipende da Attacker)
    cpd_firewall_1 = TabularCPD(
        variable="Firewall 1",
        variable_card=2,
        evidence=["Attacker"],  # Dipende da Attacker
        evidence_card=[2],
        values=[
            [1.00, 0.01],  # Firewall 1=0 (Non-Breached)
            [0.00, 0.99]   # Firewall 1=1 (Breached)
        ],
        state_names={"Firewall 1": ["Non-Breached", "Breached"],
                    "Attacker": ["Absent", "Present"]}
    )

    # Web Server (dipende da Firewall 1)
    cpd_web_server = TabularCPD(
        variable="Web Server",
        variable_card=2,
        evidence=["Firewall 1"],  # Dipende da Firewall 1
        evidence_card=[2],
        values=[
            [1.00, 0.43],  # Web Server=0 (Non-Breached)
            [0.00, 0.57]   # Web Server=1 (Breached)
        ],
        state_names={"Web Server": ["Non-Breached", "Breached"],
                    "Firewall 1": ["Non-Breached", "Breached"]}
    )

    # Email Server (dipende da Firewall 1)
    cpd_email_server = TabularCPD(
        variable="Email Server",
        variable_card=2,
        evidence=["Firewall 1"],  # Dipende da Firewall 1
        evidence_card=[2],
        values=[
            [1.00, 0.01],  # Email Server=0 (Non-Breached)
            [0.00, 0.99]   # Email Server=1 (Breached)
        ],
        state_names={"Email Server": ["Non-Breached", "Breached"],
                    "Firewall 1": ["Non-Breached", "Breached"]}
    )
    
    # Authentication Server (dipende da Web Server e Email Server)
    cpd_authentication_server = TabularCPD(
        variable="Authentication Server",
        variable_card=2,  # AS ha due stati: "Breached" e "Non-Breached"
        evidence=["Web Server", "Email Server"],  # Dipende da WS e ES
        evidence_card=[2, 2],  # WS e ES hanno entrambi due stati (Breached/Non-Breached)
        values=[
            [1.00, 0.53, 0.53, 0.28],  # AS=0 (Non-Breached)
            [0.00, 0.47, 0.47, 0.72]   # AS=1 (Breached)
        ],
        state_names={"Authentication Server": ["Non-Breached", "Breached"],
                     "Web Server": ["Non-Breached", "Breached"],
                     "Email Server": ["Non-Breached", "Breached"]}
    )
    
    # Business Server (dipende da Web Server e Email Server)
    cpd_business_server = TabularCPD(
        variable="Business Server",
        variable_card=2,  # Due stati: Breached, Non-Breached
        evidence=["Web Server", "Email Server"],  # Dipende da WS e ES
        evidence_card=[2, 2],  # Entrambi i genitori hanno due stati
        values=[
                 [1.00, 0.53, 0.53, 0.28],  # BS=0 (Non-Breached)
                 [0.00, 0.47, 0.47, 0.72]   # BS=1 (Breached)
        ],
        state_names={"Business Server": ["Non-Breached", "Breached"],
                     "Web Server": ["Non-Breached", "Breached"],
                     "Email Server": ["Non-Breached", "Breached"]}
    )
    
    # Firewall 2 (dipende da Business Server e Authentication Server)
    cpd_firewall_2 = TabularCPD(
        variable="Firewall 2",
        variable_card=2,  # Due stati: Breached, Non-Breached
        evidence=["Business Server", "Authentication Server"],  # Dipende da BS e AS
        evidence_card=[2, 2],  # Entrambi i genitori hanno due stati
        values=[
            [1.00, 0.01, 0.01, 0.0001],  # FW2=0 (Non-Breached)
            [0.00, 0.99, 0.99, 0.9999]   # FW2=1 (Breached)
        ],
        state_names={
            "Firewall 2": ["Non-Breached", "Breached"],
            "Business Server": ["Non-Breached", "Breached"],
            "Authentication Server": ["Non-Breached", "Breached"]
        }
    )

    # Application Server (dipende da Firewall 2)
    cpd_application_server = TabularCPD(
        variable="Application Server",
        variable_card=2,  # Due stati: Non-Breached, Breached
        evidence=["Firewall 2"],  # Dipende da FW2
        evidence_card=[2],  # FW2 ha due stati (Non-Breached, Breached)
        values=[
            [1.00, 0.01],  # AS=0 (Non-Breached)
            [0.00, 0.99]   # AS=1 (Breached)
        ],
        state_names={
            "Application Server": ["Non-Breached", "Breached"],
            "Firewall 2": ["Non-Breached", "Breached"]
        }
    )

    # Historian (dipende da Firewall 2)
    cpd_historian = TabularCPD(
        variable="Historian",
        variable_card=2,  # Due stati: Non-Breached, Breached
        evidence=["Firewall 2"],  # Dipende da FW2
        evidence_card=[2],  # FW2 ha due stati
        values=[
            [1.00, 0.28],  # H=0 (Non-Breached)
            [0.00, 0.72]   # H=1 (Breached)
        ],
        state_names={
            "Historian": ["Non-Breached", "Breached"],
            "Firewall 2": ["Non-Breached", "Breached"]
        }
    )

    # Firewall 3 (dipende da Application Server e Historian)
    cpd_firewall_3 = TabularCPD(
        variable="Firewall 3",
        variable_card=2,  # Due stati: Non-Breached, Breached
        evidence=["Application Server", "Historian"],  # Dipende da AS e H
        evidence_card=[2, 2],  # Entrambi i genitori hanno due stati
        values=[
            [1.00, 0.69, 0.69, 0.48],  # FW3=0 (Non-Breached)
            [0.00, 0.31, 0.31, 0.52]   # FW3=1 (Breached)
        ],
        state_names={
            "Firewall 3": ["Non-Breached", "Breached"],
            "Application Server": ["Non-Breached", "Breached"],
            "Historian": ["Non-Breached", "Breached"]
        }
    )

    # Firewall 4 (dipende da Application Server e Historian)
    cpd_firewall_4 = TabularCPD(
        variable="Firewall 4",
        variable_card=2,  # Due stati: Non-Breached, Breached
        evidence=["Application Server", "Historian"],  # Dipende da AS e H
        evidence_card=[2, 2],  # Entrambi i genitori hanno due stati
        values=[
            [1.00, 0.69, 0.69, 0.48],  # FW4=0 (Non-Breached)
            [0.00, 0.31, 0.31, 0.52]   # FW4=1 (Breached)
        ],
        state_names={
            "Firewall 4": ["Non-Breached", "Breached"],
            "Application Server": ["Non-Breached", "Breached"],
            "Historian": ["Non-Breached", "Breached"]
        }
    )

    # Local HMI 1 (dipende da Firewall 3)
    cpd_local_hmi_1 = TabularCPD(
        variable="Local HMI 1",
        variable_card=2,  # Due stati: Non-Breached, Breached
        evidence=["Firewall 3"],  # Dipende da FW3
        evidence_card=[2],  # FW3 ha due stati
        values=[
            [1.00, 0.80],  # HMI1=0 (Non-Breached)
            [0.00, 0.20]   # HMI1=1 (Breached)
        ],
        state_names={
            "Local HMI 1": ["Non-Breached", "Breached"],
            "Firewall 3": ["Non-Breached", "Breached"]
        }
    )

    # Local HMI 2 (dipende da Firewall 4)
    cpd_local_hmi_2 = TabularCPD(
        variable="Local HMI 2",
        variable_card=2,  # Due stati: Non-Breached, Breached
        evidence=["Firewall 4"],  # Dipende da FW4
        evidence_card=[2],  # FW4 ha due stati
        values=[
            [1.00, 0.53],  # HMI2=0 (Non-Breached)
            [0.00, 0.47]   # HMI2=1 (Breached)
        ],
        state_names={
            "Local HMI 2": ["Non-Breached", "Breached"],
            "Firewall 4": ["Non-Breached", "Breached"]
        }
    )

    # PLC 1 (dipende da Local HMI 1)
    cpd_plc_1 = TabularCPD(
        variable="PLC 1",
        variable_card=2,  # Due stati: Non-Breached, Breached
        evidence=["Local HMI 1"],  # Dipende da HMI1
        evidence_card=[2],  # HMI1 ha due stati
        values=[
            [1.00, 0.01],  # PLC1=0 (Non-Breached)
            [0.00, 0.99]   # PLC1=1 (Breached)
        ],
        state_names={
            "PLC 1": ["Non-Breached", "Breached"],
            "Local HMI 1": ["Non-Breached", "Breached"]
        }
    )

    # PLC 2 (dipende da Local HMI 2)
    cpd_plc_2 = TabularCPD(
        variable="PLC 2",
        variable_card=2,  # Due stati: Non-Breached, Breached
        evidence=["Local HMI 2"],  # Dipende da HMI2
        evidence_card=[2],  # HMI2 ha due stati
        values=[
            [1.00, 0.53],  # PLC2=0 (Non-Breached)
            [0.00, 0.47]   # PLC2=1 (Breached)
        ],
        state_names={
            "PLC 2": ["Non-Breached", "Breached"],
            "Local HMI 2": ["Non-Breached", "Breached"]
        }
    )

    model.add_cpds(cpd_attacker, cpd_firewall_1, cpd_web_server, cpd_email_server,
                   cpd_authentication_server, cpd_business_server, cpd_firewall_2,
                   cpd_application_server, cpd_historian, cpd_firewall_3, cpd_firewall_4,
                   cpd_local_hmi_1, cpd_local_hmi_2, cpd_plc_1, cpd_plc_2)

    # Controllo se il modello è corretto
    assert model.check_model()
    print("Modello corretto")

    # Analisi del modello
    analyze_model(model)

if __name__ == '__main__':
    main()