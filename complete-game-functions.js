// Complete Game Modal Functions
// Add these to your totalfooty-WORKING-FIXED.html

let completeGameData = {
    gameId: null,
    winningTeam: null,
    beefEntries: [],
    disciplineRecords: [],
    motmNominees: []
};

async function openCompleteGame(gameId) {
    completeGameData = {
        gameId: gameId,
        winningTeam: null,
        beefEntries: [],
        disciplineRecords: [],
        motmNominees: []
    };
    
    try {
        const token = localStorage.getItem('tf_token');
        
        // Get game details and players
        const [gameRes, playersRes] = await Promise.all([
            fetch(`${API_URL}/api/games/${gameId}`, {
                headers: { 'Authorization': `Bearer ${token}` }
            }),
            fetch(`${API_URL}/api/games/${gameId}/players`, {
                headers: { 'Authorization': `Bearer ${token}` }
            })
        ]);
        
        const game = await gameRes.json();
        const players = await playersRes.json();
        
        // Get teams if they exist
        let redTeam = [], blueTeam = [];
        if (game.team_selection_type !== 'vs_external') {
            const teamsRes = await fetch(`${API_URL}/api/admin/games/${gameId}/teams`, {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            const teamsData = await teamsRes.json();
            redTeam = teamsData.redTeam || [];
            blueTeam = teamsData.blueTeam || [];
        }
        
        showCompleteGameModal(game, players, redTeam, blueTeam);
        
    } catch (error) {
        console.error('Open complete game error:', error);
        alert('Failed to load game data');
    }
}

function showCompleteGameModal(game, players, redTeam, blueTeam) {
    const modal = document.getElementById('teamsModal');
    const content = document.getElementById('teamsModalContent');
    
    const isExternal = game.team_selection_type === 'vs_external';
    
    // Initialize discipline records for all players
    completeGameData.disciplineRecords = players.map(p => ({
        playerId: p.player_id || p.id,
        name: p.full_name || p.alias,
        offense: 'on_time',
        points: 0,
        warning: 0
    }));
    
    content.innerHTML = `
        <h2 class="heading-font" style="font-size: 28px; font-weight: 900; margin-bottom: 24px;">
            ✓ COMPLETE GAME
        </h2>
        
        <div style="max-height: 70vh; overflow-y: auto; padding-right: 8px;">
            ${!isExternal ? `
                <!-- SELECT WINNING TEAM -->
                <div class="stat-card card-glow" style="margin-bottom: 24px;">
                    <h3 style="font-size: 20px; font-weight: 900; margin-bottom: 16px;">1. SELECT WINNING TEAM</h3>
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px;">
                        <button onclick="selectWinningTeam('red')" id="redWinBtn" class="btn-secondary" style="padding: 20px; font-size: 18px; border: 3px solid #ff3366;">
                            🔴 RED TEAM WINS
                        </button>
                        <button onclick="selectWinningTeam('blue')" id="blueWinBtn" class="btn-secondary" style="padding: 20px; font-size: 18px; border: 3px solid #3366ff;">
                            🔵 BLUE TEAM WINS
                        </button>
                    </div>
                </div>
            ` : ''}
            
            <!-- DISCIPLINARIES -->
            <div class="stat-card card-glow" style="margin-bottom: 24px;">
                <h3 style="font-size: 20px; font-weight: 900; margin-bottom: 16px;">2. RECORD DISCIPLINARIES</h3>
                <div style="max-height: 300px; overflow-y: auto;">
                    ${players.map((p, idx) => `
                        <div style="display: flex; justify-content: space-between; align-items: center; padding: 12px; background: #111; border-radius: 6px; margin-bottom: 8px;">
                            <div style="font-weight: 700;">${p.full_name || p.alias}</div>
                            <select onchange="updateDiscipline(${idx}, this.value)" style="background: #000; color: #fff; border: 2px solid #333; border-radius: 4px; padding: 8px; font-weight: 700;">
                                <option value="on_time">On Time (0 pts)</option>
                                <option value="late_drop">Late Drop Out (2 pts, ⚠️0)</option>
                                <option value="5_10_late">5-10 Min Late (3 pts, ⚠️1)</option>
                                <option value="10_late">10+ Min Late (5 pts, ⚠️2)</option>
                                <option value="no_show">No Show (7 pts, ⚠️3)</option>
                            </select>
                        </div>
                    `).join('')}
                </div>
            </div>
            
            <!-- BEEF ENTRY -->
            <div class="stat-card card-glow" style="margin-bottom: 24px;">
                <h3 style="font-size: 20px; font-weight: 900; margin-bottom: 16px;">3. ENTER BEEF</h3>
                <div style="display: grid; grid-template-columns: 1fr 1fr 100px auto; gap: 12px; margin-bottom: 16px;">
                    <select id="beefPlayer1" style="background: #000; color: #fff; border: 2px solid #333; border-radius: 4px; padding: 8px;">
                        <option value="">Select Player 1</option>
                        ${players.map(p => `<option value="${p.player_id || p.id}">${p.full_name || p.alias}</option>`).join('')}
                    </select>
                    <select id="beefPlayer2" style="background: #000; color: #fff; border: 2px solid #333; border-radius: 4px; padding: 8px;">
                        <option value="">Select Player 2</option>
                        ${players.map(p => `<option value="${p.player_id || p.id}">${p.full_name || p.alias}</option>`).join('')}
                    </select>
                    <select id="beefLevel" style="background: #000; color: #fff; border: 2px solid #333; border-radius: 4px; padding: 8px;">
                        <option value="1">⭐ 1</option>
                        <option value="2">⭐ 2</option>
                        <option value="3">⭐ 3</option>
                        <option value="4">⭐ 4</option>
                        <option value="5">⭐ 5</option>
                    </select>
                    <button onclick="addBeef()" class="btn-primary">ADD</button>
                </div>
                <div id="beefList"></div>
            </div>
            
            <!-- MOTM SETUP -->
            <div class="stat-card card-glow" style="margin-bottom: 24px;">
                <h3 style="font-size: 20px; font-weight: 900; margin-bottom: 16px;">4. MAN OF THE MATCH</h3>
                ${!isExternal ? `
                    <p style="color: #999; margin-bottom: 16px;">
                        Winning team players are auto-nominated. Add up to 99 players from losing team:
                    </p>
                    <div id="motmNominees" style="max-height: 200px; overflow-y: auto;"></div>
                ` : `
                    <p style="color: #999; margin-bottom: 16px;">Select up to 99 players for MOTM voting:</p>
                    <div id="motmNominees" style="max-height: 200px; overflow-y: auto;">
                        ${players.map(p => `
                            <label style="display: block; padding: 8px; background: #111; border-radius: 6px; margin-bottom: 8px; cursor: pointer;">
                                <input type="checkbox" value="${p.player_id || p.id}" onchange="toggleMOTMNominee(this)" style="margin-right: 8px;">
                                <span style="font-weight: 700;">${p.full_name || p.alias}</span>
                            </label>
                        `).join('')}
                    </div>
                `}
            </div>
        </div>
        
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-top: 24px;">
            <button onclick="closeCompleteGameModal()" class="btn-secondary">CANCEL</button>
            <button onclick="submitCompleteGame()" class="btn-primary">COMPLETE & START MOTM VOTING</button>
        </div>
    `;
    
    modal.classList.add('active');
    
    // If not external, auto-select winning team nominees
    if (!isExternal && completeGameData.winningTeam) {
        updateMOTMNomineesDisplay(game, players, redTeam, blueTeam);
    }
}

function selectWinningTeam(team) {
    completeGameData.winningTeam = team;
    
    // Update button styles
    document.getElementById('redWinBtn').style.background = team === 'red' ? '#ff3366' : '';
    document.getElementById('redWinBtn').style.color = team === 'red' ? '#000' : '';
    document.getElementById('blueWinBtn').style.background = team === 'blue' ? '#3366ff' : '';
    document.getElementById('blueWinBtn').style.color = team === 'blue' ? '#000' : '';
    
    // Will update MOTM display
    // updateMOTMNomineesDisplay() would go here if we had game/teams data in scope
}

function updateDiscipline(index, offense) {
    const offenseData = {
        'on_time': { points: 0, warning: 0, text: 'On Time' },
        'late_drop': { points: 2, warning: 0, text: 'Late Drop Out' },
        '5_10_late': { points: 3, warning: 1, text: '5-10 Min Late' },
        '10_late': { points: 5, warning: 2, text: '10+ Min Late' },
        'no_show': { points: 7, warning: 3, text: 'No Show' }
    };
    
    const data = offenseData[offense];
    completeGameData.disciplineRecords[index].offense = offense;
    completeGameData.disciplineRecords[index].points = data.points;
    completeGameData.disciplineRecords[index].warning = data.warning;
}

function addBeef() {
    const player1 = document.getElementById('beefPlayer1').value;
    const player2 = document.getElementById('beefPlayer2').value;
    const level = document.getElementById('beefLevel').value;
    
    if (!player1 || !player2) {
        alert('Select both players');
        return;
    }
    
    if (player1 === player2) {
        alert('Cannot create beef between same player');
        return;
    }
    
    const player1Name = document.getElementById('beefPlayer1').selectedOptions[0].text;
    const player2Name = document.getElementById('beefPlayer2').selectedOptions[0].text;
    
    completeGameData.beefEntries.push({
        player1: player1,
        player2: player2,
        level: parseInt(level),
        player1Name: player1Name,
        player2Name: player2Name
    });
    
    updateBeefList();
    
    // Reset
    document.getElementById('beefPlayer1').value = '';
    document.getElementById('beefPlayer2').value = '';
    document.getElementById('beefLevel').value = '1';
}

function updateBeefList() {
    const list = document.getElementById('beefList');
    
    if (completeGameData.beefEntries.length === 0) {
        list.innerHTML = '<p style="color: #666;">No beef entries</p>';
        return;
    }
    
    list.innerHTML = completeGameData.beefEntries.map((beef, idx) => `
        <div style="display: flex; justify-content: space-between; align-items: center; padding: 12px; background: #111; border-radius: 6px; margin-bottom: 8px;">
            <div>
                <span style="font-weight: 700;">${beef.player1Name}</span>
                <span style="color: #999;"> vs </span>
                <span style="font-weight: 700;">${beef.player2Name}</span>
                <span style="color: var(--tf-accent); margin-left: 12px;">${'⭐'.repeat(beef.level)}</span>
            </div>
            <button onclick="removeBeef(${idx})" class="btn-secondary" style="padding: 4px 12px;">REMOVE</button>
        </div>
    `).join('');
}

function removeBeef(index) {
    completeGameData.beefEntries.splice(index, 1);
    updateBeefList();
}

function toggleMOTMNominee(checkbox) {
    const playerId = checkbox.value;
    
    if (checkbox.checked) {
        if (!completeGameData.motmNominees.includes(playerId)) {
            completeGameData.motmNominees.push(playerId);
        }
    } else {
        const idx = completeGameData.motmNominees.indexOf(playerId);
        if (idx > -1) {
            completeGameData.motmNominees.splice(idx, 1);
        }
    }
    
    // Limit to 99
    if (completeGameData.motmNominees.length > 99) {
        checkbox.checked = false;
        completeGameData.motmNominees.pop();
        alert('Maximum 99 nominees');
    }
}

async function submitCompleteGame() {
    // Validation
    if (!completeGameData.gameId) {
        alert('Invalid game ID');
        return;
    }
    
    // Prepare data
    const gameData = {
        winningTeam: completeGameData.winningTeam,
        disciplineRecords: completeGameData.disciplineRecords.filter(d => d.points > 0),
        beefEntries: completeGameData.beefEntries,
        motmNominees: completeGameData.motmNominees
    };
    
    try {
        const token = localStorage.getItem('tf_token');
        const response = await fetch(`${API_URL}/api/admin/games/${completeGameData.gameId}/complete`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(gameData)
        });
        
        if (!response.ok) {
            throw new Error('Failed to complete game');
        }
        
        alert('✓ Game completed! MOTM voting is now open for 24 hours.');
        closeCompleteGameModal();
        loadAdminGames();
        
    } catch (error) {
        console.error('Complete game error:', error);
        alert('Failed to complete game: ' + error.message);
    }
}

function closeCompleteGameModal() {
    document.getElementById('teamsModal').classList.remove('active');
    completeGameData = {
        gameId: null,
        winningTeam: null,
        beefEntries: [],
        disciplineRecords: [],
        motmNominees: []
    };
}
